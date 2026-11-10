package org.bouncycastle.pkix.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;

/**
 * Name constraint processing in PKIXCertPathReviewer must not be driven into unbounded
 * work by a certificate carrying a huge subject alternative name extension, checked against
 * huge name constraints inherited from the CAs above it.
 * <p>
 * The chains are built in code: root -&gt; ca1 -&gt; ca2 -&gt; leaf, where the CAs carry
 * large permitted/excluded DNS name constraints and ca2/leaf carry large subject alternative
 * name lists that all fall inside the permitted subtrees.
 * </p>
 */
public class CheckNameConstraintsTest
    extends TestCase
{
    // the limit PKIXCertPathReviewer applies to the subject alternative names of a certificate
    private static final int NAME_CHECK_MAX = 1 << 10;

    private static final int PERMITTED_COUNT = 1500;
    private static final int EXCLUDED_COUNT = 500;
    private static final int SAN_COUNT = 1500;

    private static final String SUBJ_ALT_NAME_EXT_ERROR = "CertPathReviewer.subjAltNameExtError";
    private static final String NOT_PERMITTED_NAME_ERROR = "CertPathReviewer.notPermittedEmail";

    // index of ca2 in the reviewed path (leaf = 0, ca2 = 1, ca1 = 2, root is the trust anchor)
    private static final int CA2_INDEX = 1;

    private static BigInteger serialNumber = BigInteger.ONE;

    private static KeyPair rootKp;
    private static KeyPair ca1Kp;
    private static KeyPair ca2Kp;
    private static KeyPair leafKp;

    public void testPKIXCertPathReviewer()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate[] chain = createChain(createSubjectAltNames("ca2-", SAN_COUNT, null), true,
            createSubjectAltNames("leaf-", SAN_COUNT, null));

        PKIXCertPathReviewer certPathReviewer = review(chain);

        assertFalse("path with an oversized subjectAltName list accepted: " + describeErrors(certPathReviewer),
            certPathReviewer.isValidCertPath()); // hit
        assertTrue("oversized subjectAltName list of ca2 not rejected: " + describeErrors(certPathReviewer),
            containsError(certPathReviewer.getErrors(CA2_INDEX), SUBJ_ALT_NAME_EXT_ERROR));
    }

    public void testPKIXCertPathReviewerNameCheckLimit()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // exactly at the limit - every name is checked and every name is permitted.
        X509Certificate[] chain = createChain(createSubjectAltNames("ca2-", NAME_CHECK_MAX, null), false,
            createSubjectAltNames("leaf-", 1, null));

        PKIXCertPathReviewer certPathReviewer = review(chain);

        assertTrue("path with " + NAME_CHECK_MAX + " subjectAltNames rejected: " + describeErrors(certPathReviewer),
            certPathReviewer.isValidCertPath());
        assertFalse("subjectAltName list at the limit reported as oversized",
            containsError(certPathReviewer.getErrors(CA2_INDEX), SUBJ_ALT_NAME_EXT_ERROR));

        // one past the limit - rejected without checking the names.
        chain = createChain(createSubjectAltNames("ca2-", NAME_CHECK_MAX + 1, null), false,
            createSubjectAltNames("leaf-", 1, null));

        certPathReviewer = review(chain);

        assertFalse("path with " + (NAME_CHECK_MAX + 1) + " subjectAltNames accepted: " + describeErrors(certPathReviewer),
            certPathReviewer.isValidCertPath());
        assertTrue("subjectAltName list past the limit not rejected: " + describeErrors(certPathReviewer),
            containsError(certPathReviewer.getErrors(CA2_INDEX), SUBJ_ALT_NAME_EXT_ERROR));
    }

    public void testPKIXCertPathReviewerChecksNamesWithinLimit()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // a list within the limit is still checked against the name constraints.
        GeneralName outside = new GeneralName(GeneralName.dNSName, "host.not-permitted.example.net");

        X509Certificate[] chain = createChain(createSubjectAltNames("ca2-", NAME_CHECK_MAX - 1, outside), false,
            createSubjectAltNames("leaf-", 1, null));

        PKIXCertPathReviewer certPathReviewer = review(chain);

        assertFalse("path with a non-permitted subjectAltName accepted: " + describeErrors(certPathReviewer),
            certPathReviewer.isValidCertPath());
        assertTrue("non-permitted subjectAltName of ca2 not reported: " + describeErrors(certPathReviewer),
            containsError(certPathReviewer.getErrors(CA2_INDEX), NOT_PERMITTED_NAME_ERROR));
        assertFalse("subjectAltName list within the limit reported as oversized",
            containsError(certPathReviewer.getErrors(CA2_INDEX), SUBJ_ALT_NAME_EXT_ERROR));
    }

    public void testPKIXCertPathBuilder()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        X509Certificate rootCert = makeRoot();
        X509Certificate endCert = makeCa1(rootCert);

        // create CertStore to support path building
        List list = new ArrayList();
        list.add(endCert);

        CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
        CertStore                     store = CertStore.getInstance("Collection", params, "BC");

        // build the path
        CertPathBuilder  builder = CertPathBuilder.getInstance("PKIX", "BC");
        X509CertSelector pathConstraints = new X509CertSelector();

        pathConstraints.setCertificate(endCert);

        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), pathConstraints);

        buildParams.addCertStore(store);
        buildParams.setDate(new Date());
        buildParams.setRevocationEnabled(false);

        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
        CertPath                  path = result.getCertPath();

        if (path.getCertificates().size() != 1)
        {
            fail("wrong number of certs in testPKIXCertPathBuilder path");
        }
    }

    public void testPKIXCertPathValidator()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate rootCert = makeRoot();
        X509Certificate endCert = makeCa1(rootCert);

        List list = new ArrayList();
        list.add(endCert);

        CertPath certPath = cf.generateCertPath(list);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(rootCert, null));

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "BC");
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        cpv.validate(certPath, param);
    }

    private static PKIXCertPathReviewer review(X509Certificate[] chain)
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        List certchain = new ArrayList();
        for (int i = 0; i != chain.length; i++)
        {
            certchain.add(chain[i]);
        }

        CertPath cp = cf.generateCertPath(certchain);

        Set trust = new HashSet();
        trust.add(new TrustAnchor(chain[chain.length - 1], null));
        PKIXParameters param = new PKIXParameters(trust);
        param.setRevocationEnabled(false);

        PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
        certPathReviewer.init(cp, param);

        return certPathReviewer;
    }

    private static boolean containsError(List errors, String id)
    {
        for (Iterator it = errors.iterator(); it.hasNext();)
        {
            ErrorBundle msg = (ErrorBundle)it.next();
            if (id.equals(msg.getId()))
            {
                return true;
            }
        }
        return false;
    }

    private static String describeErrors(PKIXCertPathReviewer certPathReviewer)
    {
        List[] errors = certPathReviewer.getErrors();
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i != errors.length; i++)
        {
            sb.append('[').append(i - 1).append(':');
            for (Iterator it = errors[i].iterator(); it.hasNext();)
            {
                sb.append(' ').append(((ErrorBundle)it.next()).getId());
            }
            sb.append(']');
        }

        return sb.toString();
    }

    /**
     * Build root -&gt; ca1 -&gt; ca2 -&gt; leaf, returned in path order (leaf first, root last).
     */
    private static X509Certificate[] createChain(GeneralNames ca2AltNames, boolean ca2Constraints, GeneralNames leafAltNames)
        throws Exception
    {
        X509Certificate root = makeRoot();
        X509Certificate ca1 = makeCa1(root);
        X509Certificate ca2 = makeCertificate(ca1, getCa1Kp().getPrivate(), getCa2Kp().getPublic(),
            "CN=Mal CA2, O=Bouncy Castle, C=AU", true,
            ca2Constraints ? createNameConstraints() : null, ca2AltNames);
        X509Certificate leaf = makeCertificate(ca2, getCa2Kp().getPrivate(), getLeafKp().getPublic(),
            "CN=Mal Leaf, O=Bouncy Castle, C=AU", false, null, leafAltNames);

        return new X509Certificate[] { leaf, ca2, ca1, root };
    }

    private static X509Certificate makeRoot()
        throws Exception
    {
        return TestUtil.makeTrustAnchor(getRootKp(), "CN=Mal Root, O=Bouncy Castle, C=AU");
    }

    private static X509Certificate makeCa1(X509Certificate root)
        throws Exception
    {
        return makeCertificate(root, getRootKp().getPrivate(), getCa1Kp().getPublic(),
            "CN=Mal CA1, O=Bouncy Castle, C=AU", true, createNameConstraints(), null);
    }

    private static X509Certificate makeCertificate(X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey,
        String subject, boolean isCA, NameConstraints nameConstraints, GeneralNames subjectAltNames)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            issuer.getSubjectX500Principal(),
            allocateSerialNumber(),
            new Date(now - 1000L * 60),
            new Date(now + (1000L * 60 * 60 * 24 * 100)),
            new X500Principal(subject),
            subjectKey);

        v3CertGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        if (isCA)
        {
            v3CertGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        }

        if (nameConstraints != null)
        {
            v3CertGen.addExtension(Extension.nameConstraints, true, nameConstraints);
        }

        if (subjectAltNames != null)
        {
            v3CertGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC");

        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issuerKey)));

        cert.verify(issuer.getPublicKey());

        return cert;
    }

    /**
     * DNS name constraints: PERMITTED_COUNT permitted subtrees pN.example.com and
     * EXCLUDED_COUNT excluded subtrees xN.example.org.
     */
    private static NameConstraints createNameConstraints()
    {
        GeneralSubtree[] permitted = new GeneralSubtree[PERMITTED_COUNT];
        for (int i = 0; i != permitted.length; i++)
        {
            permitted[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "p" + i + ".example.com"));
        }

        GeneralSubtree[] excluded = new GeneralSubtree[EXCLUDED_COUNT];
        for (int i = 0; i != excluded.length; i++)
        {
            excluded[i] = new GeneralSubtree(new GeneralName(GeneralName.dNSName, "x" + i + ".example.org"));
        }

        return new NameConstraints(permitted, excluded);
    }

    /**
     * count DNS names, each inside one of the permitted subtrees of createNameConstraints(),
     * followed by extra (if not null).
     */
    private static GeneralNames createSubjectAltNames(String prefix, int count, GeneralName extra)
    {
        GeneralName[] names = new GeneralName[(extra == null) ? count : count + 1];
        for (int i = 0; i != count; i++)
        {
            names[i] = new GeneralName(GeneralName.dNSName, prefix + i + ".p" + (i % PERMITTED_COUNT) + ".example.com");
        }
        if (extra != null)
        {
            names[count] = extra;
        }

        return new GeneralNames(names);
    }

    private static synchronized BigInteger allocateSerialNumber()
    {
        BigInteger serial = serialNumber;
        serialNumber = serialNumber.add(BigInteger.ONE);
        return serial;
    }

    private static synchronized KeyPair getRootKp()
        throws Exception
    {
        if (rootKp == null)
        {
            rootKp = generateKeyPair();
        }
        return rootKp;
    }

    private static synchronized KeyPair getCa1Kp()
        throws Exception
    {
        if (ca1Kp == null)
        {
            ca1Kp = generateKeyPair();
        }
        return ca1Kp;
    }

    private static synchronized KeyPair getCa2Kp()
        throws Exception
    {
        if (ca2Kp == null)
        {
            ca2Kp = generateKeyPair();
        }
        return ca2Kp;
    }

    private static synchronized KeyPair getLeafKp()
        throws Exception
    {
        if (leafKp == null)
        {
            leafKp = generateKeyPair();
        }
        return leafKp;
    }

    private static KeyPair generateKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");

        kpGen.initialize(1024, new SecureRandom());

        return kpGen.generateKeyPair();
    }
}
