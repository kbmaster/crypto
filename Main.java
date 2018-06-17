import java.io.*;

public class Main{

	
   static public void main(String argv[]) {    
     try {
		Crypto.parse(argv);
	      
    	} catch (Exception e) {
		
	  //System.out.println(e.getMessage());
	  e.printStackTrace();	
    }
  }


}


