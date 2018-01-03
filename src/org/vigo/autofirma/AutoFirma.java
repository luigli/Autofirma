/**
 * Clase principal
 */
package org.vigo.autofirma;

import es.gob.afirma.cert.signvalidation.DataAnalizerUtil;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.util.logging.Logger;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOInvalidFormatException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.AOSimpleSignInfo;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;
import es.gob.afirma.keystores.KeyStoreUtilities;
import es.gob.afirma.keystores.mozilla.MozillaKeyStoreUtilities;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.cades.CAdESValidator;
import es.gob.afirma.signers.multi.cades.AOCAdESCounterSigner;
import es.gob.afirma.signers.xades.AOXAdESSigner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/**
 * Pruebas simples de almacenes Mozilla NSS.
 */
public final class AutoFirma {

    private static final String CATCERT_POLICY = "0.4.0.2023.1.1"; //$NON-NLS-1$
    private static final String CATCERT_TSP = "http://psis.catcert.net/psis/catcert/tsp"; //$NON-NLS-1$
    private static final Boolean CATCERT_REQUIRECERT = Boolean.TRUE;
    private static final Properties[] CADES_MODES;

    static {
        final Properties p1 = new Properties();
        p1.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        p1.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$

        final Properties p2 = new Properties();
        p2.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        p2.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$
        p2.setProperty("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.8"); //$NON-NLS-1$ //$NON-NLS-2$
        p2.setProperty("policyIdentifierHash", "7SxX3erFuH31TvAw9LZ70N7p1vA="); //$NON-NLS-1$ //$NON-NLS-2$
        p2.setProperty("policyIdentifierHashAlgorithm", "http://www.w3.org/2000/09/xmldsig#sha1"); //$NON-NLS-1$ //$NON-NLS-2$
        //p2.setProperty("policyQualifier", "http://www.google.com"); //$NON-NLS-1$ //$NON-NLS-2$

        final Properties p3 = new Properties();
        p3.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        p3.setProperty("mode", AOSignConstants.SIGN_MODE_EXPLICIT); //$NON-NLS-1$

        final Properties p4 = new Properties();
        p4.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        p4.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$
        p4.put("tsaURL", CATCERT_TSP); //$NON-NLS-1$
        p4.put("tsaPolicy", CATCERT_POLICY); //$NON-NLS-1$
        p4.put("tsaRequireCert", CATCERT_REQUIRECERT); //$NON-NLS-1$
        p4.put("tsaHashAlgorithm", "SHA-512"); //$NON-NLS-1$ //$NON-NLS-2$

        CADES_MODES = new Properties[]{
            p1, p2, p3
        };
    }

    /**
     * Inicio de las pruebas desde consola sin JUnit.
     *
     * @param args No se usa.
     * @throws Exception En cualquier error.
     */
    public static void main(final String[] args) throws Exception {
        System.out.println(MozillaKeyStoreUtilities.getMozillaUserProfileDirectory());
        //new AutoFirma().testKeyStoreManagerCreation();
        //new AutoFirma().pruebaXAdES();
        //new AutoFirma().verifySignature("/home/luis/Descargas/firma5.xsig");
        XAdES xades = new XAdES();
        xades.cargaDatosFirma("/home/luis/Descargas/firma3.xsig");
        System.out.println(xades.getFirmantesLong());
        System.out.println(xades.getNombreDocumento());
        
    }

    /**
     * Indica si el fichero está firmado
     *
     * @param datos
     * @return
     */
    public Boolean estaFirmado(byte[] datos) {
        return DataAnalizerUtil.isSignedBinary(datos)
                || DataAnalizerUtil.isSignedFacturae(datos)
                || DataAnalizerUtil.isSignedXML(datos);
    }

    /**
     * Indica si el fichero es un PDF
     *
     * @param datos
     * @return
     */
    public Boolean esPDF(byte[] datos) {
        return DataAnalizerUtil.isPDF(datos);
    }

    /**
     * AutoFirma de la obtenci&oacute;n de almac&eacute;n y alias con Mozilla
     * NSS.
     *
     * @throws Exception En cualquier error.
     */
    @SuppressWarnings("static-method")
    public void testKeyStoreManagerCreation() throws Exception {
        final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(
                AOKeyStore.MOZ_UNI, // Store
                null, // Lib
                "TEST-KEYSTORE", // Description //$NON-NLS-1$
                null, // PasswordCallback
                null // Parent
        );
        System.out.println("Certificados:"); //$NON-NLS-1$
        System.out.println("-------------"); //$NON-NLS-1$
        final String[] aliases = ksm.getAliases();
        for (final String alias : aliases) {
            System.out.println(AOUtil.getCN(ksm.getCertificate(alias)));
        }
        System.out.println("============="); //$NON-NLS-1$

        final Signature sig = Signature.getInstance("SHA512withRSA"); //$NON-NLS-1$
        sig.initSign(ksm.getKeyEntry(aliases[0]).getPrivateKey());
        sig.update("Hola".getBytes()); //$NON-NLS-1$
        System.out.println("Firma: " + AOUtil.hexify(sig.sign(), false)); //$NON-NLS-1$
        final AOSigner signer = new AOCAdESSigner();
        PrivateKeyEntry pke = ksm.getKeyEntry(aliases[0]);

        Properties p3 = new Properties();
        p3.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        p3.setProperty("mode", AOSignConstants.SIGN_MODE_EXPLICIT); //$NON-NLS-1$

        byte[] datos;
        datos = AOUtil.getDataFromInputStream(new FileInputStream("/home/luis/tabla.ods"));
        final byte[] result = signer.sign(
                datos,
                AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
                pke.getPrivateKey(),
                pke.getCertificateChain(),
                p3
        );
        final File saveFile = File.createTempFile("firmado", ".csig"); //$NON-NLS-1$ //$NON-NLS-2$
        try (
                final OutputStream os = new FileOutputStream(saveFile);) {
            os.write(result);
            os.flush();
        }
        byte[] firmado = AOUtil.getDataFromInputStream(new FileInputStream(saveFile));
        Boolean valido = CAdESValidator.isCAdESValid(firmado, true);
        System.out.println("Firma válida: " + valido);

        AOCAdESCounterSigner signer2 = new AOCAdESCounterSigner();
        Properties config = new Properties();
        final byte[] result2 = signer2.countersign(
                firmado,
                AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
                CounterSignTarget.TREE,
                null,
                pke.getPrivateKey(),
                pke.getCertificateChain(),
                config
        );
        final File tempFile = File.createTempFile("contrafirmado", ".csig");
        try (
                final OutputStream fos = new FileOutputStream(tempFile);) {
            fos.write(result2);
        }
        AOCAdESSigner sig3 = new AOCAdESSigner();
        AOTreeModel tree = sig3.getSignersStructure(result2, true);
        AOSimpleSignInfo simpleSignInfo = (AOSimpleSignInfo) ((AOTreeNode) tree.getRoot()).getChildAt(0).getUserObject();
        X509Certificate[] certs = simpleSignInfo.getCerts();
        for (X509Certificate cert : certs) {
            X500Principal p = cert.getSubjectX500Principal();
            String formato = "RFC1779";
            String dn = p.getName(formato);
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                System.out.println("LDAP: " + rdn.getType() + " -> " + rdn.getValue());
            }
            System.out.println("Certif: " + p.getName(formato));
            //System.out.println("Certif: " + cert.toString());
        }

    }

    /**
     * Recorre la cadena y devuelve los NIFs encontrados
     *
     * @param s
     * @return
     */
    public ArrayList<String> getNIFs(String s) {
        ArrayList<String> result = new ArrayList<String>();
        String[] campos = s.split(" ");
        for (String c : campos) {
            try {
                if (c.length() == 9 && Integer.parseInt(c.substring(1, 8)) > 0) {
                    result.add(c);
                }
            } catch (NumberFormatException ex) {
            }

        }
        return result;
    }

    public void recorreFirmas(AOTreeNode n) {
        for (int i = 0; i < n.getChildCount(); i++) {
            try {
                AOTreeNode h = n.getChildAt(i);
                //recorreFirmas(h);
                AOSimpleSignInfo simpleSignInfo = (AOSimpleSignInfo) h.getUserObject();
                X509Certificate cert = simpleSignInfo.getCerts()[0];
                String cn = AOUtil.getCN(cert);
                System.out.println(getNIFs(cn) + " " + cn);
                System.out.println("Fecha: " 
                        + Fechas.ddmmaaaa_hhmmss(simpleSignInfo.getSigningTime()));
                //System.out.println("Formato: " + simpleSignInfo.getSignAlgorithm());
            } catch (Exception ex) {
                Logger.getLogger(AutoFirma.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void pruebaXAdES() throws Exception {
        PrivateKeyEntry clave = Certificados.getPrimerCertificadoMozilla();
        byte[] datos = AOUtil.getDataFromInputStream(new FileInputStream("/home/luis/Descargas/firma4.xsig"));
        byte[] result = XAdES.firma(datos, clave);
        OutputStream os = new FileOutputStream("/home/luis/Descargas/firma5.xsig");
        os.write(result);
        os.flush();
        os.close();

    }

    public void verifySignature(String fichero) throws Exception {
        byte[] firmado = AOUtil.getDataFromInputStream(new FileInputStream(fichero));
        if (DataAnalizerUtil.isSignedXML(firmado)) {
            System.out.println("Firmado xsig");
            AOXAdESSigner signer = new AOXAdESSigner();
            AOTreeModel tree = signer.getSignersStructure(firmado, true);
            AOTreeNode n = (AOTreeNode) tree.getRoot();
            recorreFirmas(n);
        }
    }

}
