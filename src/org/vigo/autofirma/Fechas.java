/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.vigo.autofirma;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author luis
 */
public class Fechas {
    public static String ddmmaaaa_hhmmss(Date d){
        SimpleDateFormat df = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
        return df.format(d);
    }
    
}
