JFLAGS=-g
JAVA=java
JAVAC=javac

JARS = -cp "./libs/org-apache-commons-codec.jar"
JAR=jar


Main.class: Main.java Crypto.java APDU.java

compile: Main.java Crypto.java APDU.java
	$(JAVAC)  $(FLAGS) $(JARS)  $(PKGS) $^

run: Main.class
	 $(JAVA)  Main  

jar: Main.class Crypto.class APDU.class
	$(JAR) cmvf MANIFEST.MF crypto.jar $^	

clean:
	rm -rf  *.jar *.class *~
