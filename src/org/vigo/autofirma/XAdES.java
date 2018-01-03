/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.vigo.autofirma;

import es.gob.afirma.cert.signvalidation.DataAnalizerUtil;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.MimeHelper;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSimpleSignInfo;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signers.cades.CAdESExtraParams;
import es.gob.afirma.signers.xades.AOXAdESSigner;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 *
 * @author luis
 */
public class XAdES {

    private String firmantesLong;
    private String nombreDocumento;
    private byte[] documentoOriginal;
    private ArrayList<Certificado> certificados = new ArrayList<Certificado>();

    public static byte[] firma(byte[] datos, KeyStore.PrivateKeyEntry clave) throws Exception {
        Properties prop = new Properties();
        prop.setProperty("format", AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
        prop.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$
        // Los valores de clave relacionados con la tsa se pueden ver en 
        // es.gob.afirma.signers.cades.CAdESExtraParams
        //prop.setProperty("tsaURL", "http://tsu.camerfirma.com:5003/ts.inx");
        prop.setProperty("tsaURL", "http://psis.catcert.net/psis/catcert/tsp");
        prop.setProperty("tsaPolicy", "0.4.0.2023.1.1");
        //prop.setProperty("tsaUsr", "itsa2p0104");
        //prop.setProperty("tsaPwd", "pN2I_m6v");
        prop.put("tsaRequireCert", Boolean.TRUE); //$NON-NLS-1$
        prop.put("tsaHashAlgorithm", "SHA-512"); //$NON-NLS-1$ //$NON-NLS-2$

        return firma(datos, clave, AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA, prop);
    }

    public static byte[] firma(byte[] datos, KeyStore.PrivateKeyEntry clave, String algoritmo, Properties parametros)
            throws Exception {
        byte[] result;
        if (DataAnalizerUtil.isSignedBinary(datos)) {
            // Si ya está firmado, añadimos una contrafirma
            AOXAdESSigner signer = new AOXAdESSigner();
            result = signer.countersign(
                    datos,
                    AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
                    CounterSignTarget.TREE,
                    null,
                    clave.getPrivateKey(),
                    clave.getCertificateChain(),
                    parametros
            );
        } else {
            AOXAdESSigner signer = new AOXAdESSigner();
            result = signer.sign(
                    datos,
                    AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
                    clave.getPrivateKey(),
                    clave.getCertificateChain(),
                    parametros
            );
        }
        return result;
    }

    private void recorreFirmas(AOTreeNode n) {
        for (int i = 0; i < n.getChildCount(); i++) {
            try {
                AOTreeNode h = n.getChildAt(i);
                //recorreFirmas(h);
                AOSimpleSignInfo simpleSignInfo = (AOSimpleSignInfo) h.getUserObject();
                certificados.add(new Certificado(simpleSignInfo));
                X509Certificate cert509 = simpleSignInfo.getCerts()[0];
                X500Principal principal = cert509.getSubjectX500Principal();
                Certificado cert = new Certificado(simpleSignInfo);
                String formato = "RFC1779";
                String dn = principal.getName(formato);
                LdapName ldapDN = new LdapName(dn);
                for (Rdn rdn : ldapDN.getRdns()) {
                    //System.out.println("LDAP: " + rdn.getType() + " -> " + rdn.getValue());
                }

                //System.out.println(cert.toString());
                String cn = AOUtil.getCN(cert509);
                if (firmantesLong.length() > 0) {
                    firmantesLong += " & ";
                }
                firmantesLong += cert.toString() + " - "//cn + " - "
                        + Fechas.ddmmaaaa_hhmmss(simpleSignInfo.getSigningTime());
            } catch (Exception ex) {
                Logger.getLogger(AutoFirma.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void cargaDatosFirma(String nombreFichero) throws Exception {
        byte[] datos = AOUtil.getDataFromInputStream(new FileInputStream(nombreFichero));
        cargaDatosFirma(datos);
    }

    public void cargaDatosFirma(byte[] datos) throws Exception {
        firmantesLong = "";
        if (DataAnalizerUtil.isSignedXML(datos)) {
            AOXAdESSigner signer = new AOXAdESSigner();
            byte[] original = signer.getData(datos);
            if (Base64.isBase64(original)) {
                documentoOriginal = Base64.decode(original, 0, original.length, false);
                MimeHelper mh = new MimeHelper(documentoOriginal);
                nombreDocumento = "Documento." + mh.getExtension();
            } else {
                System.out.println("No es B64");
                byte[] tmp = signer.getData(original);
                if (Base64.isBase64(original)) {
                    byte[] t3 = Base64.decode(tmp, 0, tmp.length, false);
                    MimeHelper mh = new MimeHelper(t3);
                    nombreDocumento = "Documento." + mh.getExtension();
                }
                MimeHelper mh = new MimeHelper(original);
                System.out.println("" + mh.getExtension());
            }
            AOTreeModel tree = signer.getSignersStructure(datos, true);
            AOTreeNode n = (AOTreeNode) tree.getRoot();
            recorreFirmas(n);
        }
    }

    public String getNombreDocumento() {
        return this.nombreDocumento;
    }

    public String getFirmantesLong() throws Exception {
        return firmantesLong;
    }

}
