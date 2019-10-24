#NOME:							| RA:
#Breno Baldovinotti 			| 14315311
#Caroline Gerbaudo Nakazato 	| 17164260
#Marco Antônio de Nadai Filho 	| 16245961
#Nícolas Leonardo Külzer Kupka 	| 16104325
#Paulo Mangabeira Birocchi 		| 16148363
#------------------------------------------

#obj-m+=proj1.o
obj-m+=cryptochar.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) teste.c -o teste_userspace
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm teste_userspace
