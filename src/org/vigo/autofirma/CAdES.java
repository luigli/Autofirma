/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.vigo.autofirma;

import es.gob.afirma.cert.signvalidation.DataAnalizerUtil;
import es.gob.afirma.core.AOException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.cades.AOCAdESSigner;
import es.gob.afirma.signers.multi.cades.AOCAdESCounterSigner;
import java.security.KeyStore;
import java.util.Properties;

/**
 *
 * @author luis
 */
public class CAdES {

    public byte[] firma(byte[] datos, KeyStore.PrivateKeyEntry clave) throws Exception {
        Properties prop = new Properties();
        prop.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
        prop.setProperty("mode", AOSignConstants.SIGN_MODE_EXPLICIT); //$NON-NLS-1$
        

        return firma(datos, clave, AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA, prop);
    }

    public byte[] firma(byte[] datos, KeyStore.PrivateKeyEntry clave, String algoritmo, Properties parametros)
            throws Exception {
        byte[] result;
        if (DataAnalizerUtil.isSignedBinary(datos)) {
            // Si ya está firmado, añadimos una contrafirma
            AOCAdESCounterSigner signer = new AOCAdESCounterSigner();
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
            AOCAdESSigner signer = new AOCAdESSigner();
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
}
