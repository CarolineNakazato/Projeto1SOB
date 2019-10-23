#include <linux/init.h>             // Macros used to mark up functions e.g. __init __exit
#include <crypto/internal/skcipher.h>
#include <crypto/internal/hash.h> 
#include <linux/module.h>           // Core header for loading LKMs into the kernel
#include <linux/crypto.h>
#include <linux/device.h>           // Header to support the kernel Driver Model
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel
#include <linux/fs.h>               // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/mutex.h>

#define KEY_SIZE 16
#define ENCRYPT 0
#define DECRYPT 1

static char *key = "0102030405060708A1A2A3A4A5A6A7A8";
static char *iv  = "0102030405060708A1A2A3A4A5A6A7A8";
module_param(key, charp, 0); //permissao 0, so no insmod
module_param(iv, charp, 0);

struct tcrypt_result {
    struct completion completion;
    int err;
};

struct skcipher_def {
    struct scatterlist in;
    struct scatterlist out;
    struct crypto_skcipher * tfm;
    struct skcipher_request * req;
    struct tcrypt_result result;
    char * scratchpad;
    char * ciphertext;
    unsigned char * key;
    unsigned char * ivdata;
};

static struct skcipher_def sk;

typedef struct message {
    char * data;
    int blocks;
} message;

//******************************************************************************************//
//                      FILE MANIPULATION ETC                                               //
#define  DEVICE_NAME "crypto"       ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "crypto"       ///< The device class -- this is a character device driver
#define     BUFF_SIZE 256
static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   msg[BUFF_SIZE] = {0};       ///< Memory for the string that is passed from userspace
static short  size_of_msg;              ///< Used to remember the size of the string stored
static struct class*  cryptocharClass  = NULL; ///< The device-driver class struct pointer
static struct device* cryptocharDevice = NULL; ///< The device-driver device struct pointer
// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
};
static char op;
//static unsigned char user_buff[BUFF_SIZE];
static unsigned char * user_buff;
static DEFINE_MUTEX(mutex_1);
static DEFINE_MUTEX(mutex_usrbuff);
static short read_times;
//******************************************************************************************//

//******************************************************************************************//
//                      FUNCOES                                                             //
void getRAWString(unsigned char * RAWout, char * str, int key_size){
    int i,j;
    char c[2];
    for(i=0;i<key_size;i++){
        for(j=0;j<2;j++){
            c[j] = str[i*2+j];
            if(c[j] >= 'A' && c[j] <= 'F')
                c[j] = c[j] - 'A' + 10;
            else if(c[j] >= '0' && c[j] <= '9')
                c[j] = c[j] - '0';
            else{
                printk(KERN_WARNING "ERRO: O texto \'%c\' (0x%x) nao corresponde a um valor HEXA valido..\n",c[0],c[0]);
            }
        }
        RAWout[i] = c[0] * 16 + c[1];
    }
}
unsigned char * alloc_RAWString(char * str, int key_size){
    char * tmp = kmalloc(1+(key_size*2), GFP_KERNEL);
    unsigned char * ret = kmalloc(key_size+1, GFP_KERNEL);
    
    int i;
    if(strlen(str) >= key_size*2){
        for(i=0;i<key_size*2;i++){
            tmp[i]=str[i];
        }
    }
    else{//faco o padding se necessario na key ou iv
        for(i=0;i<strlen(str);i++){
            tmp[i]=str[i];
        }
        for(i=strlen(str);i<key_size*2;i++){
            tmp[i]='0';
        }
    }
    getRAWString(ret,tmp,key_size);
    kfree(tmp);
    return ret;
}
message * alloc_with_padding(char * str, int key_size){
    message * M = kmalloc(sizeof(message), GFP_KERNEL);
    int blocks=0, end_pos=0, i=0;
    if (strlen(str) < key_size || strlen(str)%key_size != 0){
        //calcula blocos e memoria a ser alocada
        blocks=strlen(str)/key_size;
        end_pos=strlen(str)%key_size;
        M->data = kmalloc(1+(key_size*(blocks+1)), GFP_KERNEL); //alloca nova memoria relativo ao bloco atual
        if (!M->data) {
            pr_info("Nao foi possivel alocar o texto a ser encriptado\n");
            return NULL;
        }
        for(i=0;i<strlen(str);i++){
            M->data[i]=str[i];
        }
        for(i=end_pos; i<key_size ;i++){
            M->data[i+(blocks * key_size)]= '\0';//''#';
        }
        M->data[i+(blocks * key_size)]='\0';
        pr_info("PADDING EXECUTADO!\n");
        M->blocks=blocks+1;
    }
    else{ //se for uma string com o padding correto só aloca
        M->data = kmalloc(1+strlen(str), GFP_KERNEL);
        for(i=0;i<strlen(str);i++){
            M->data[i]=str[i];
            M->blocks=strlen(str)/key_size;
        }
    }
    return M;
}
//******************************************************************************************//
static int skcipher_result(struct skcipher_def * sk, int rc);
static void skcipher_callback(struct crypto_async_request *req, int error);
static void skcipher_finish(struct skcipher_def * sk);
//******************************************************************************************//
static int aes_enc_dec(int mode, message * input, struct skcipher_def * sk){
    int ret = -EFAULT;
    //Alocar handle de cifra com chave simétrica (tfm)
    if (!sk->tfm) {
        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", CRYPTO_ALG_TYPE_ABLKCIPHER, 0);
        //sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
        if (IS_ERR(sk->tfm)) {
            pr_info("Nao foi possivel alocar o handle de cifra (TFM)\n");
            return PTR_ERR(sk->tfm);
        }
    }
    //Alocar handle de request na memoria do kernel
    if (!sk->req) {
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
        if (!sk->req) {
            pr_info("Nao foi possivel alocar o request na memoria do kernel\n");
            ret = -ENOMEM;
            return ret;
        }
    }
    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  skcipher_callback,
                                  &sk->result);

    if (!sk->key) {
        pr_info("Falha ao encontrar parametro KEY\n");
        return ret;
    }
    /* AES 128 with given symmetric key */
    if (crypto_skcipher_setkey(sk->tfm, sk->key, KEY_SIZE)) {
        pr_info("A Chave Criptografica nao pode ser configurada\n");
        ret = -EAGAIN;
        return ret;
    }
    // Inicialization Vector
    if (!sk->ivdata) {
        pr_info("Falha ao encontrar parametro IV\n");
        return ret;
    }

    /*pr_info("----------DEBUG_ONLY---------------\n");
    for(i=0;i<KEY_SIZE;i++){
        pr_info("key[%d]=0x%X\tiv[%d]=0x%X\n", i , sk->key[i] , i , sk->ivdata[i]);
    }*/

    //STRING PARA A SAIDA !!!!!!!!!!!!!!!! 
    if (!sk->ciphertext) {
        sk->ciphertext = kmalloc(KEY_SIZE*input->blocks, GFP_KERNEL);
        if (!sk->ciphertext) {
            pr_info("Nao foi possivel alocar o vetor de saida (ciphertext)\n");
            return ret;
        }
    }
    memset(sk->ciphertext,'\0',KEY_SIZE*input->blocks);

    sg_init_one(&sk->in, input->data, KEY_SIZE*input->blocks);
    sg_init_one(&sk->out, sk->ciphertext, KEY_SIZE*input->blocks);
    //FUNCAO PRINCIPAL DE CRITOGRAFIA!!!
    skcipher_request_set_crypt(sk->req, &sk->in, &sk->out,
                               KEY_SIZE*input->blocks, sk->ivdata);
    init_completion(&sk->result.completion);

    if(mode <= 0){
        pr_info("ENCRYPT AES128 OPERATION:\n");
        ret = crypto_skcipher_encrypt(sk->req);
    }
    else
    {
        pr_info("DECRYPT AES128 OPERATION:\n");
        ret = crypto_skcipher_decrypt(sk->req);
    }
        
    ret = skcipher_result(sk, ret);
    if (ret)
        return ret;

    pr_info("Encryption request successful\n");
    return ret;

}
//******************************************************************************************//
static void skcipher_callback(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;

    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

static int skcipher_result(struct skcipher_def * sk, int rc)
{
    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }

    init_completion(&sk->result.completion);

    return rc;
}

static void skcipher_finish(struct skcipher_def * sk)
{
    if (sk->tfm)
        crypto_free_skcipher(sk->tfm);
    if (sk->req)
        skcipher_request_free(sk->req);
    if (sk->key)
        kfree(sk->key);
    if (sk->ivdata)
        kfree(sk->ivdata);
    if (sk->ciphertext)
        kfree(sk->ciphertext);
}
//= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =//
//= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =//
int cryptoapi_init(char * input)
{
    int i;
    sk.tfm = NULL;
    sk.req = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = alloc_RAWString(iv, KEY_SIZE);
    sk.key = alloc_RAWString(key, KEY_SIZE);
    //aqui o input eh texto!!! plaintext
    message * INPUT = alloc_with_padding(input, KEY_SIZE);
    aes_enc_dec(ENCRYPT, INPUT, &sk);

    
    //APRESENTACAO DO RESULTADO DA ENCRIPTACAO..
    char * txt = sg_virt(&sk.out);
    if(mutex_is_locked(&mutex_usrbuff)){
        printk(KERN_ALERT "ENCRYPT: Cant LOCK USER_BUFF MUTEX, NEED TO READ FIRST\n");
    }
    mutex_lock(&mutex_usrbuff);
    size_of_msg = KEY_SIZE*INPUT->blocks;
    user_buff = kmalloc(size_of_msg+1, GFP_KERNEL);
    memset(user_buff,'\0',size_of_msg+1);

    for (i = 0;i<size_of_msg; i++){
        user_buff[i]=(unsigned char)txt[i];
        pr_info("sg[%d]= 0x%02X\n",i, user_buff[i]);
	}
    //user_buff[size_of_msg]='\0';
    

    //kfree(txt);
    kfree(INPUT->data);
    kfree(INPUT);
    skcipher_finish(&sk);
    return 0;
}

int decryptoapi_init(char * input)
{
    int i;
    sk.tfm = NULL;
    sk.req = NULL;
    sk.ciphertext = NULL;
    sk.ivdata = alloc_RAWString(iv, KEY_SIZE);
    sk.key = alloc_RAWString(key, KEY_SIZE);
    //aqui o input eh hexa!!
    //32 chars = 16 bytes
    message INPUT;

    INPUT.blocks = strlen(input)/(KEY_SIZE*2);
    if(strlen(input)%(KEY_SIZE*2) != 0)
        INPUT.blocks++;
    INPUT.data = (unsigned char *) alloc_RAWString(input,KEY_SIZE*INPUT.blocks);
    
    aes_enc_dec(DECRYPT, &INPUT, &sk);

    //APRESENTACAO DO RESULTADO DA ENCRIPTACAO..
    char * txt = sg_virt(&sk.out);
    if(mutex_is_locked(&mutex_usrbuff)){
        printk(KERN_ALERT "DECRYPT: Cant LOCK USER_BUFF MUTEX, NEED TO READ FIRST\n");
    }
    mutex_lock(&mutex_usrbuff);
    size_of_msg = KEY_SIZE*INPUT.blocks;
    user_buff = kmalloc(size_of_msg+1, GFP_KERNEL);
    memset(user_buff,'\0',size_of_msg+1);

    for (i = 0;i<size_of_msg; i++){
        user_buff[i]=(unsigned char)txt[i];
        pr_info("sg[%d]= 0x%02X\n",i, user_buff[i]);
	}
    //user_buff[size_of_msg]='\0';

    kfree(INPUT.data);
    skcipher_finish(&sk);
    return 0;
}

// ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~//

int cryptosha1_init(char * input)
{
	char result[20];

	struct crypto_shash * sha1 = crypto_alloc_shash("sha1", 0, 0);
	struct shash_desc * shash = kmalloc(crypto_shash_descsize(sha1)+sizeof(struct shash_desc), GFP_KERNEL);

	if (IS_ERR(sha1))
		return -1;
	if (!shash)
		return -ENOMEM;

	shash->tfm = sha1;
	shash->flags = 0;

    crypto_shash_digest(shash, input, strlen(input), result);

	kfree(shash);
	crypto_free_shash(sha1);

    //APRESENTACAO DO RESULTADO DA ENCRIPTACAO..
    if(mutex_is_locked(&mutex_usrbuff)){
        printk(KERN_ALERT "ENCRYPT: Cant LOCK USER_BUFF MUTEX, NEED TO READ FIRST\n");
    }
    mutex_lock(&mutex_usrbuff);
    size_of_msg = 20;
    user_buff = kmalloc(size_of_msg+1, GFP_KERNEL);
    memset(user_buff,'\0',size_of_msg+1);
    int i;
    for (i = 0;i<size_of_msg; i++){
        user_buff[i]=(unsigned char)result[i];
        pr_info("HASH[%d]= 0x%02X\n",i, user_buff[i]);
	}

	return 0;
}


//= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =//
//= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =//
/**********************************************************************************************
**********************************************************************************************/
static int __init cryptochar_init(void){
   printk(KERN_INFO "CRYPTOChar: Initializing the CRYPTOChar LKM\n");

   printk(KERN_ALERT "key = %s\n", key);
   printk(KERN_ALERT "inicialization_vector = %s\n", iv);

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "CRYPTOChar failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "CRYPTOChar: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   cryptocharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(cryptocharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(cryptocharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "CRYPTOChar: device class registered correctly\n");

   // Register the device driver
   cryptocharDevice = device_create(cryptocharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(cryptocharDevice)){               // Clean up if there is an error
      class_destroy(cryptocharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(cryptocharDevice);
   }
   printk(KERN_INFO "CRYPTOChar: device class created correctly\n"); // Made it! device was initialized
   mutex_init(&mutex_1);
   mutex_init(&mutex_usrbuff);
   return 0;
}

static void __exit cryptochar_exit(void){
   mutex_destroy(&mutex_1);
   mutex_destroy(&mutex_usrbuff);
   device_destroy(cryptocharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(cryptocharClass);                          // unregister the device class
   class_destroy(cryptocharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "CRYPTOChar: Goodbye from the LKM!\n");
}

/**********************************************************************************************
**********************************************************************************************/


static int dev_open(struct inode *inodep, struct file *filep){
    read_times = 0;
    if(!mutex_trylock(&mutex_1)){                  // Try to acquire the mutex (returns 0 on fail)
        printk(KERN_ALERT "\nCRYPTOChar: Device in use by another process\n");
        return -EBUSY;
    }
    printk(KERN_INFO "CRYPTOChar: Device has been opened");
    return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    read_times++;
    //SEND SIZE_OF_MSG --- buffer precisa de cast pois o macro não entende..
    if(read_times <= 1){
        if(put_user(size_of_msg,(short *)buffer) != 0){
            printk(KERN_INFO "CRYPTOChar: Failed to send \"size_of_msg\" to userspace..\n");
            kfree(user_buff); //LIBERO BUFFER DINAMICO
            return -EFAULT;   // Failed -- return a bad address msg (i.e. -14)
        }
        // primeiro eu envio o tamanho da mensagem que eu quero
    }
    else{//depois a mensagem em si...
        int error_count = copy_to_user(buffer, user_buff, size_of_msg);
        // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    
        kfree(user_buff); //LIBERO BUFFER DINAMICO
        read_times=0;
        mutex_unlock(&mutex_usrbuff); //liber mutex para alocar um novo buffer

        if (error_count==0){            // if true then have success
            printk(KERN_INFO "CRYPTOChar: Sent %d characters to the user\n", size_of_msg);
            return (0);
        }
        else {
            printk(KERN_INFO "CRYPTOChar: Failed to send %d characters to the user\n", error_count);
            return -EFAULT; // Failed -- return a bad address msg (i.e. -14)
        }
    }
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    sprintf(msg, "%s", buffer);
    //size_of_msg = strlen(msg);
    op = msg[0];
    pr_info("msg = %s", msg);
    pr_info("op = %c", op);
    pr_info("size_msg = %d", strlen(msg));
    
    char * x = kmalloc(strlen(msg) - 1,GFP_KERNEL);
    int i;
    for(i=0;i<strlen(msg)-2;i++){
        x[i] = msg[i+2];
    }
    x[i] = '\0';
    pr_info("dados=%s",x);

    if(op == 'c' || op == 'C'){
        cryptoapi_init(x);
    }
    else if(op == 'd' || op == 'D'){
        decryptoapi_init(x);
    }
    else if(op == 'h' || op == 'H'){
        cryptosha1_init(x);
    }
    else{
        printk(KERN_INFO "Operacao Invalida!\n");
    }
    kfree(x);
   printk(KERN_INFO "CRYPTOChar: WRITE OK");
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
    mutex_unlock(&mutex_1);
   printk(KERN_INFO "\nCRYPTOChar: Device successfully closed\n");
   return 0;
}
module_init(cryptochar_init);
module_exit(cryptochar_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco De Nadai");
MODULE_DESCRIPTION("Projeto1 de SOB 2019");
MODULE_VERSION("0.1");