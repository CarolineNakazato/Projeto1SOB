#include <linux/init.h>      
#include <linux/module.h>         
#include <linux/device.h>         
#include <linux/kernel.h>        
#include <linux/fs.h>          
#include <asm/uaccess.h>          
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/hash.h>
#include <libelf.h>

#define  DEVICE_NAME "sob"          //< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "Crypto"       //< The device class -- this is a character device driver

static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
int doHash(char *dados);
static int mocacp_skcipher(char *word, int operation);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nícolas & Carol");

MODULE_DESCRIPTION("teste hash");
MODULE_VERSION("1.0");

static char *key = "default";
static int moduleMajorVersion;
static struct class*  moduleClass  = NULL; ///< The device-driver class struct pointer
static struct device* moduleDevice = NULL; ///< The device-driver device struct pointer
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;       

module_param(key, charp, 0000);
MODULE_PARM_DESC(key, "A key string");

static struct file_operations operacoes = 
{
  .read = dev_read,
  .write = dev_write,
};

static int __init iniciar(void)
{
    printk(KERN_INFO "Loading driver! \n");

    moduleMajorVersion = register_chrdev(0, DEVICE_NAME, &operacoes);

    if (moduleMajorVersion<0)
    {
        printk(KERN_ALERT "Device failed to receive a version\n");
        return moduleMajorVersion;
    }
    printk(KERN_INFO "Device succeeded to receive a version!\n", moduleMajorVersion);

    moduleClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(moduleClass))
    {
        unregister_chrdev(moduleMajorVersion, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create a class fot the module\n");
        return PTR_ERR(moduleClass);
    }
    printk(KERN_INFO "Module class created!\n");

    moduleDevice = device_create(moduleClass, NULL, MKDEV(moduleMajorVersion, 0), NULL, DEVICE_NAME);
    if (IS_ERR(moduleDevice))
    { 
        class_destroy(moduleClass);
        unregister_chrdev(moduleMajorVersion, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create device\n");
        return PTR_ERR(moduleDevice);
    }
    printk(KERN_INFO "Device created with success\n");

    printk(KERN_INFO "HASH KEY: %s\n",key);

    return 0;
}

static void __exit sair(void)
{
    device_destroy(moduleClass, MKDEV(moduleMajorVersion, 0));
    class_unregister(moduleClass);
    class_destroy(moduleClass);
    unregister_chrdev(moduleMajorVersion, DEVICE_NAME);
    printk(KERN_INFO "Removing driver\n");
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    char operation, space, word[len-2];
    
    operation = buffer[0];

    space = buffer[1];

    strncpy(word, buffer+2, sizeof(len-2));
    
    if (space != ' ') {
        printk(KERN_INFO "Fail to parse: %s\n", buffer);
        return 0;
    }

    typecheck(word,16);


    switch (operation) {
        case 'h':
            printk(KERN_INFO "Option ----------------------> h");
            printk(KERN_INFO "Message ---------------------> %s\n", buffer);
            return doHash(word);
            break;
        default:
            printk(KERN_INFO "Error");
            printk(KERN_INFO "Message ---------------------> %s\n", buffer);
            break;
    }

    return len;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
    int error_count = 0;
    // copy_to_user has the format ( * to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, message, size_of_message);

    if (error_count==0){            // if true then have success
        printk(KERN_INFO "HASHTest: Sent %d characters to the user\n", size_of_message);
        return (size_of_message=0);  // clear the position to the start and return 0
    }
    else {
        printk(KERN_INFO "HASHTest: Failed to send %d characters to the user\n", error_count);
        return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
    }
}

int doHash(char *dados){

    struct crypto_shash *tfm;
    struct shash_desc *desc;
    
    unsigned char digest[32];
    
    unsigned int shash_desc_size;
    int i;
    int ret;

    tfm = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);

    shash_desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);

    desc = kmalloc(shash_desc_size, GFP_KERNEL);


    desc->tfm = tfm;
    desc->flags = 0;

    ret = crypto_shash_digest(desc, dados, strlen(dados), digest);

    printk(KERN_INFO "Hash:");
    
    for(i = 0; i <= 32; i++)
    {
        printk(KERN_INFO "%02x", digest[i]);
    }

    return ret;
}



// struct com o resultado da cifragem/decifragem do conteúdo enviado
struct tcrypt_result {
    struct completion completion;
    int err;
};

// struct que define o cipher que utilizaremos
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm; // transformation é o tipo de algoritmo que usaremos, no caso ecb(aes)
    struct skcipher_request *req;// qual a função requisitada pelo user, c para cifrar, d para decifrar
    struct tcrypt_result result; // struct com resultado da cifra/decifra
};

module_init(iniciar);
module_exit(sair);


