package com.base0010.plume;


import javacard.framework.*;

public class PLUME extends Applet{

    public PLUME(){

    }

    public static void install(byte bArray[], short bOffset, byte bLength){
        PLUME Plume = new PLUME();
        Plume.register(bArray, (short)(bOffset + 1), (byte)bArray[bOffset]);
    }

    public void process(APDU apdu){
        return;
    }

}
