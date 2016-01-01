all:
	gcc contextTrace.c -o contextTrace -pthread
clean:
	rm contextTrace
