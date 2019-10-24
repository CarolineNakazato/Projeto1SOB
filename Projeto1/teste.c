//NOME:							| RA:
//Breno Baldovinotti 			| 14315311
//Caroline Gerbaudo Nakazato 	| 17164260
//Marco Antônio de Nadai Filho 	| 16245961
//Nícolas Leonardo Külzer Kupka | 16104325
//Paulo Mangabeira Birocchi 	| 16148363
//------------------------------------------

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
 
#define BUFFER_LENGTH 1024               ///< The buffer length (crude but fine)
static short size;
static unsigned char * receive;

int main(){
    int ret, fd;
    char stringToSend[BUFFER_LENGTH];

    fd = open("/dev/crypto", O_RDWR);             // Open the device with read/write access
    if (fd < 0){
        perror("Failed to open the device...");
        return errno;
    }

    //TODO FAZER ALOCACAO DINAMICA NA HORA DE LER DO USUARIO..??? SERA QUE PRECISA????
    printf("Type in a short string to send to the kernel module:\n");
    //strcpy(stringToSend,"d ECE995D2B64216FAE674690DE595F000");
    //strcpy(stringToSend,"d CA47FE6C0553A3667CF3CE843AC94C57C3955C5B57F421BDE95DC10B032512E1");
    scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)

    printf("Writing message to the device [%s].\n", stringToSend);
    ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
    if (ret < 0){
        perror("Failed to write the message to the device.");
        return errno;
    }
 
    printf("Press ENTER to read back from the device...\n");
    getchar();

    printf("Reading from the device...\n");

    if(read(fd, &size, sizeof(short)) < 0){
        perror("Failed to read the message from the device.");
        return errno;
    }
    printf("SIZE=%d\n",size);
    receive = (unsigned char *) malloc(sizeof(unsigned char)*(size+1));
    receive[size] = '\0';
    ret = read(fd,receive, size);
    if(ret < 0){
        perror("Failed to read the message from the device.");
        return errno;
    }
    printf("The received message is: \n");
    int i;
    for(i=0;i<size;i++){
        printf("msg[%d] = 0x%X = %c\n",i,receive[i],receive[i]);
    }
    free(receive);
    return 0;
}