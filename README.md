# crypto
Tarea de seguridad

Se adjunta el compilado crypto.jar

Requiere
JDK 1.8
make

make compile 		//to compile proyect <br/>
make jar 		//to create crypto.jar <br/>
java -jar crypto.jar 	//to run <br/>

////////////////////////////////////////////////////

configuracion crypto.ini  

keystore= path/to/keystore
dbhost= db_host_name
dbname= db_name
dbuser= db_username
dbpassword= bd_user_password
sessiondir= cookie_session_dir


Se adjuntan los scripts crypto.sql  para crear la base de datos

//////////////////////////////////////////////////

Ejemplos:

login:
java -jar crypto.jar -l 

firmado
java -jar crypto.jar -s documento

verificacion
java -jar crypto.jar -v documento.crt docuemnto.sgn docuemnto

logout 
java -jar crypto.jar -o




