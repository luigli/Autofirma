/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.vigo.autofirma;

import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;
import java.security.KeyStore;
import java.util.ArrayList;

/**
 *
 * @author luis
 */
public class Certificados {

    public static KeyStore.PrivateKeyEntry getPrimerCertificadoMozilla() throws Exception {
        final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(
                AOKeyStore.MOZ_UNI, // Store
                null, // Lib
                "TEST-KEYSTORE", // Description //$NON-NLS-1$
                null, // PasswordCallback
                null // Parent
        );
        return ksm.getKeyEntry(ksm.getAliases()[0]);
    }

    public static String[] getNIFs(String s) {
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
        String list[] = new String[result.size()];
        return result.toArray(list);
    }

}
