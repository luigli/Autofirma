/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.vigo.autofirma;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSimpleSignInfo;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author luis
 */
public class Certificado {

    private final String OID_NOMBRE = "OID.2.5.4.42";
    private final String OID_APELLIDO = "OID.2.5.4.4";
    private final String OID_NIF = "OID.2.5.4.5";
    private final String OID_CARGO = "OID.2.5.4.12";
    private final String OID_O = "O";
    private final String OID_TIPO = "OID.2.5.4.13";
    private final String OID_OU = "OID.2.5.4.4";
    
    private String DN;
    private String CN;
    private String[] NIFs;
    private String NIF;
    private String nombre;
    private String apellidos;
    private String cargo;
    private String o;
    private String tipo;
    private Date fechaFirma;
    private String datosExtra = "";

    public Certificado(AOSimpleSignInfo simpleSignInfo) {
        X509Certificate cert = simpleSignInfo.getCerts()[0];
        X500Principal p = cert.getSubjectX500Principal();
        String formato = "RFC1779";
        String dn = p.getName(formato);
        try {
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (OID_NOMBRE.equals(rdn.getType())){ 
                    this.nombre = rdn.getValue().toString();
                }
                if (OID_APELLIDO.equals(rdn.getType())){ 
                    this.apellidos = rdn.getValue().toString();
                }
                if (OID_NIF.equals(rdn.getType())){ 
                    this.NIF = rdn.getValue().toString();
                }
                if (OID_CARGO.equals(rdn.getType())){ 
                    this.cargo = rdn.getValue().toString();
                }
                if (OID_O.equals(rdn.getType())){ 
                    this.o = rdn.getValue().toString();
                }
                if (OID_TIPO.equals(rdn.getType())){ 
                    this.tipo = rdn.getValue().toString();
                }
            }
        } catch (Exception ex) {    }
        String cn = AOUtil.getCN(cert);
        this.DN = cert.getSubjectDN().toString();
        this.CN = cn;
        this.NIFs = Certificados.getNIFs(cn);
        this.fechaFirma = simpleSignInfo.getSigningTime();
    }

    public String getNombre() {
        return "nombre";
    }

    public String getFechaFirmaFormateada() {
        return Fechas.ddmmaaaa_hhmmss(fechaFirma);
    }

    public String[] getNIFs() {
        return NIFs;
    }

    @Override
    public String toString() {
        if (nombre != null && apellidos != null && cargo != null && o != null){
            return nombre+" "+apellidos+" - "+cargo+ " - " + o;
        } else {
            return CN;
        }
    }

}
