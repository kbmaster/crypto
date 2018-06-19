
JFLAGS=-g
JAVA=java
JAVAC=javac

JARS = -cp "./libs/bcprov-jdk15on-159.jar"
JAR=jar


Main.class:*.java 

compile: *.java
	$(JAVAC)  $(FLAGS) $(JARS)  $(PKGS) $^

run: Main.class
	 $(JAVA)  Main  

jar: *.class
	$(JAR) cmvf MANIFEST.MF crypto.jar $^	

clean:
	rm -rf  *.jar *.class *~
