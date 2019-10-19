obj-m+=projeto1.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) teste.c -o teste_userspace
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm teste_userspace
