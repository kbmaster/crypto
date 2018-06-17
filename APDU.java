import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminal;

class APDU
{
		
	//////////////////////
	private static String __signature="";
	private static CardChannel __channel=null;
	////////////////////	
	

	public static boolean verifyPIN(String PIN) throws Exception
	{
		CardChannel channel= APDU.getChannel();
		if(!APDU.selectIAS(channel))throw new Exception("No se puede acceder a la tarjeta");

		String CLASS = "00";
	        String INSTRUCTION = "20";
        	String PARAM1 = "00";
        	String PARAM2 = "11";

		String HexPIN=APDU.PinToAsciiHex(PIN);
		
	        byte CLASSbyte = APDU.hexStringToByteArray(CLASS)[0];
	        byte INSbyte = APDU.hexStringToByteArray(INSTRUCTION)[0];
        	byte P1byte = APDU.hexStringToByteArray(PARAM1)[0];
        	byte P2byte = APDU.hexStringToByteArray(PARAM2)[0];
        	ResponseAPDU r = APDU.sendCommand(channel, CLASSbyte, INSbyte, P1byte, P2byte,  APDU.hexStringToByteArray(HexPIN),0);
		
		return (r.getSW1() == (int) 0x90 && r.getSW2() == (int) 0x00);

	}

	public static String sign (String hash) throws Exception
	{
		CardChannel channel= APDU.getChannel();
		if(!APDU.MSE_SET_DST(channel))throw new Exception("No se pudo seleccionar el algoritmo de firmado");
		if(!APDU.PSO_HASH(channel,hash))throw new Exception("No se pudo procesar el hash");
		if(!APDU.PSO_CDS(channel)) throw new Exception("No se pudo procesar la firma");
		
		//si lleo hasta aca entonces pudo firmar
		return APDU.__signature;

	}

	//COMMANDS///////////////////////////////////////////////////////////////////////
	

	private static  CardChannel getChannel() throws Exception
	{
		
		if(APDU.__channel!=null) return APDU.__channel;

		TerminalFactory factory = TerminalFactory.getDefault();
        	List<CardTerminal> terminals = factory.terminals().list();
        	CardTerminal terminal = terminals.get(0);
        	Card card = terminal.connect("T=0");
		CardChannel channel = card.getBasicChannel();
		APDU.__channel=channel;
		return APDU.__channel;
	}	



	private static boolean selectIAS(CardChannel channel) throws Exception 
	{
        	String CLASS = "00";
        	String INSTRUCTION = "A4";
	        String PARAM1 = "04";
        	String PARAM2 = "00";

	        String dataIN = "A00000001840000001634200"; //IAS AID

        	byte CLASSbyte = APDU.hexStringToByteArray(CLASS)[0];
        	byte INSbyte = APDU.hexStringToByteArray(INSTRUCTION)[0];
        	byte P1byte = APDU.hexStringToByteArray(PARAM1)[0];
        	byte P2byte = APDU.hexStringToByteArray(PARAM2)[0];
        	ResponseAPDU r = APDU.sendCommand(channel, CLASSbyte, INSbyte, P1byte, P2byte, APDU.hexStringToByteArray(dataIN), 0);
        	return (r.getSW1() == (int) 0x90 && r.getSW2() == (int) 0x00);
    	}

	 //Set Algoritm
	 private static boolean MSE_SET_DST(CardChannel channel) throws Exception
	 {

        	String CLASS = "00";
        	String INSTRUCTION = "22";
        	String PARAM1 = "41";
        	String PARAM2 = "B6";

        	String dataIN = "840101800102"; // Select the key pair (RSA/ECC) and the

        	byte CLASSbyte = APDU.hexStringToByteArray(CLASS)[0];
        	byte INSbyte = APDU.hexStringToByteArray(INSTRUCTION)[0];
        	byte P1byte = APDU.hexStringToByteArray(PARAM1)[0];
        	byte P2byte = APDU.hexStringToByteArray(PARAM2)[0];
        	ResponseAPDU r = APDU.sendCommand(channel, CLASSbyte, INSbyte, P1byte, P2byte, APDU.hexStringToByteArray(dataIN), 0);
        	return (r.getSW1() == (int) 0x90 && r.getSW2() == (int) 0x00);

        	// El SW 6A80 indica error de codificacion, es decir, en los TLV
        	// El SW 63Cx indica error de match y que quedan x intentos
        	// 9000 es SW de exito
    	}

	//Process hash
	private static boolean PSO_HASH(CardChannel channel,String hash) throws Exception
	{
        	String CLASS = "00";
        	String INSTRUCTION = "2A";
	        String PARAM1 = "90";
        	String PARAM2 = "A0";

        	String length = APDU.byteArrayToHex(APDU.intToByteArray(hash.length() / 2));

	        String dataIN = "90"; // Select the key pair (RSA/ECC) and the signature
        	dataIN += length;
        	dataIN += hash;

        	byte CLASSbyte = APDU.hexStringToByteArray(CLASS)[0];
        	byte INSbyte = APDU.hexStringToByteArray(INSTRUCTION)[0];
        	byte P1byte = APDU.hexStringToByteArray(PARAM1)[0];
        	byte P2byte = APDU.hexStringToByteArray(PARAM2)[0];
        	ResponseAPDU r = APDU.sendCommand(channel, CLASSbyte, INSbyte, P1byte, P2byte, 	APDU.hexStringToByteArray(dataIN), 0);

        	return (r.getSW1() == (int) 0x90 && r.getSW2() == (int) 0x00);

        	// El SW 6A80 indica error de codificacion, es decir, en los TLV
        	// El SW 63Cx indica error de match y que quedan x intentos
        	// 9000 es SW de exito
    	}

	//Compute Digital Signature
	private static boolean PSO_CDS(CardChannel channel) throws Exception
	{

        	String CLASS = "00";
        	String INSTRUCTION = "2A";
        	String PARAM1 = "9E";
        	String PARAM2 = "9A";

        	String dataIN = "";

        	byte CLASSbyte = APDU.hexStringToByteArray(CLASS)[0];
        	byte INSbyte = APDU.hexStringToByteArray(INSTRUCTION)[0];
        	byte P1byte = APDU.hexStringToByteArray(PARAM1)[0];
        	byte P2byte = APDU.hexStringToByteArray(PARAM2)[0];
        	ResponseAPDU r = APDU.sendCommand(channel, CLASSbyte, INSbyte, P1byte, P2byte, APDU.hexStringToByteArray(dataIN), 0);

	        APDU.__signature = APDU.byteArrayToHex(r.getData());

        	return (r.getSW1() == (int) 0x90 && r.getSW2() == (int) 0x00);

        	// El SW 6A80 indica error de codificacion, es decir, en los TLV
        	// El SW me parec 63Cx indica error de match y que quedan x intentos
        	// 9000 es SW de exito
		
	}


	//UTILS///////////////////////////////////////////////////////////
	
	private static byte[] hexStringToByteArray(String s) 
	{
        	int len = s.length();
        	byte[] data = new byte[len / 2];
        	for (int i = 0; i < len; i += 2) 
		{
            		data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        	}
        
		return data;
	}

	private static byte[] intToByteArray(int a) 
	{
        	byte[] b;
        	if (a >= 256) 
		{
            		b = new byte[2];
            		b[0] = (byte) (a / 256);
            		b[1] = (byte) (a % 256);
        	} else 
		{
            		b = new byte[1];
            		b[0] = (byte) a;
        	}

        	return b;
	}

	public static String byteArrayToHex(byte[] a) 
	{
        	StringBuilder sb = new StringBuilder(a.length * 2);
        	for (byte b : a) {
            		sb.append(String.format("%02X", b));
        	}
        	return sb.toString();
    	}

	
	private static String PinToAsciiHex(String pin) 
	{

        	//Return an Hex representation of the input Pin.
        	//Each byte in hex represent an ascii digit.
        	String pinAscii = "";

	        for (int i = 0; i < pin.length(); i++) {
          	  char c = pin.charAt(i);
          	  String hex = Integer.toHexString((int) c);
           	 pinAscii = pinAscii.concat(hex);
        	}

        	//Padding with 00 to complete 12 bytes
        	int padding = (24 - pinAscii.length()) / 2;

        	for (int j = 0; j < padding; j++) {
            		pinAscii += "00";
        	}

        	return pinAscii;
	}
	

	private static ResponseAPDU sendCommand(CardChannel chan, byte CLASS, byte INS, byte P1, byte P2, byte[] data, int le) throws Exception
	{
        	int length = data.length; // largo de la data a mandar
        	int i = 0;
        	int iteraciones = 0;
        	int SW1 = 0, SW2 = 0;
        	byte[] command;
        	ResponseAPDU r = null;

        	//si datain vacio
        	// mando el comando con LE solo
        	if (length == 0) 
		{
            		//Si le distinto de 0 lo agrego al final de command           
            		command = new byte[5];
            		command[0] = CLASS;
            		command[1] = INS;
            		command[2] = P1;
            		command[3] = P2;
            		command[4] = intToByteArray(le)[0];
            		r = chan.transmit(new CommandAPDU(command));
            		SW1 = r.getSW1();
            		SW2 = r.getSW2();
		}

		while (length - i > 0) 
		{
            
			iteraciones++;
            	
			if (length - i > 0xFF) 
			{
                		command = new byte[255 + 6]; //le al final
                		command[261] = intToByteArray(le)[0];
                		command[0] = (byte) (CLASS | 0x10);
                		command[4] = (byte) 0xFF; // mando el maximo de datos que puedo
                		System.arraycopy(data, i, command, 5, 0xFF);

            		} else 
			{
                		if (le > 0 || (le == 0 && length == 0)) 
				{
                    			command = new byte[length - i + 6];
                    			command[length - i + 6 - 1] = intToByteArray(le)[0];//le al final
                		} else 
				{
                    			command = new byte[length - i + 5]; //sin  le al final
                		}

                		command[0] = CLASS;
                		command[4] = (byte) (length - i); // mando el maximo de datos
                		// que puedo
                		System.arraycopy(data, i, command, 5, length - i);
            		}
            
			command[1] = INS;
            		command[2] = P1;
            		command[3] = P2;

			r = chan.transmit(new CommandAPDU(command));
            		SW1 = r.getSW1();
            		SW2 = r.getSW2();

            		i += 0xFF;

        	}
		
		return r;
	

	}	



}
