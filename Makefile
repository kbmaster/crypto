JFLAGS=-g
JAVA=java
JAVAC=javac
JAR=jar

Main.class: Main.java Crypto.java

compile: Main.java Crypto.java
	$(JAVAC)  $(FLAGS) $^

run: Main.class
	 $(JAVA)  Main 

jar: Main.class Crypto.class
	$(JAR) cmvf MANIFEST.MF crypto.jar Main.class Crypto.class	

clean:
	rm -f  *.jar *.class *~
