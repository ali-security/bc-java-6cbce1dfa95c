package org.bouncycastle.pkix.test;

import java.io.IOException;
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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
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
import org.bouncycastle.pkix.PKIXNameConstraintValidator;
import org.bouncycastle.pkix.PKIXNameConstraintValidatorException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;
import org.bouncycastle.util.Properties;

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
    private static final String NOT_PERMITTED_DN_ERROR = "CertPathReviewer.notPermittedDN";

    private static final String SGP22_NAME_CONSTRAINTS = "org.bouncycastle.x509.sgp22_name_constraints";

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

    /**
     * A directoryName permitted constraint must match as an INITIAL PREFIX of the subject
     * (RFC 5280 sec. 4.2.1.10 / 7.1), not as a subsequence at an arbitrary offset. Prepending an
     * RDN ahead of the permitted sequence must not satisfy the constraint.
     */
    public void testDirectoryNameConstraintIsInitialPrefix()
        throws Exception
    {
        GeneralName permittedDN = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prefixSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prependedSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US, o=Injected"));

        assertTrue("prefix subject must be permitted", isPermitted(permittedDN, prefixSubject));
        assertFalse("subject with an RDN prepended before the permitted sequence must NOT be permitted",
            isPermitted(permittedDN, prependedSubject));

        GeneralName trustedOrg = directoryName("C=US,O=TrustedOrg");

        assertTrue("subject under C=US,O=TrustedOrg must be permitted",
            isPermitted(trustedOrg, directoryName("C=US,O=TrustedOrg,CN=victim")));
        assertFalse("C=FR,O=Attacker prepended ahead of C=US,O=TrustedOrg must NOT be permitted",
            isPermitted(trustedOrg, directoryName("C=FR,O=Attacker,C=US,O=TrustedOrg,CN=victim")));
        assertTrue("an excluded prefix must still be excluded",
            isExcluded(trustedOrg, directoryName("C=US,O=TrustedOrg,CN=victim")));
    }

    /**
     * The relaxed anywhere-match for GSMA SGP.22 is still available, but only when explicitly
     * enabled through org.bouncycastle.x509.sgp22_name_constraints.
     */
    public void testDirectoryNameConstraintSGP22OptIn()
        throws Exception
    {
        GeneralName trustedOrg = directoryName("C=US,O=TrustedOrg");
        GeneralName prepended = directoryName("C=FR,O=Attacker,C=US,O=TrustedOrg,CN=victim");

        assertFalse("relaxed matching must be off by default", isPermitted(trustedOrg, prepended));

        Properties.setThreadOverride(SGP22_NAME_CONSTRAINTS, true);
        try
        {
            assertTrue("relaxed matching must apply once opted in", isPermitted(trustedOrg, prepended));
        }
        finally
        {
            Properties.removeThreadOverride(SGP22_NAME_CONSTRAINTS);
        }

        assertFalse("relaxed matching must be off again", isPermitted(trustedOrg, prepended));
    }

    /**
     * An RFC 1034 root-label trailing dot must not let a host escape an excluded rfc822Name, URI or
     * dNSName subtree: the host is canonicalised before it is compared.
     */
    public void testTrailingDotBypass()
        throws Exception
    {
        assertTrue("trailing-dot email must be caught by the excluded bank.com subtree",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot email must be caught by the excluded mailbox",
            isExcluded(emailName("ceo@bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot email must be caught by the excluded .bank.com domain",
            isExcluded(emailName(".bank.com"), emailName("ceo@mail.bank.com.")));
        assertTrue("trailing-dot URI host must be caught by the excluded competitor.example subtree",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example./")));
        assertTrue("trailing-dot URI host must be caught by the excluded .competitor.example domain",
            isExcluded(uriName(".competitor.example"), uriName("https://www.competitor.example./")));
        assertTrue("trailing-dot DNS name must be caught by the excluded bank.com subtree",
            isExcluded(dnsName("bank.com"), dnsName("bank.com.")));
        assertTrue("trailing-dot DNS name must be caught by the excluded bank.com subtree",
            isExcluded(dnsName("bank.com"), dnsName("www.bank.com.")));

        // canonicalisation is symmetric: a fully-qualified name is still within its permitted subtree
        assertTrue("trailing-dot email must still be permitted",
            isPermitted(emailName("bank.com"), emailName("ceo@bank.com.")));
        assertTrue("trailing-dot URI host must still be permitted",
            isPermitted(uriName("competitor.example"), uriName("https://competitor.example./")));
        assertTrue("trailing-dot DNS name must still be permitted",
            isPermitted(dnsName("bank.com"), dnsName("www.bank.com.")));

        // and other hosts are unaffected
        assertFalse("trailing-dot email on another host must not be excluded",
            isExcluded(emailName("bank.com"), emailName("ceo@notbank.com.")));
        assertFalse("trailing-dot URI on another host must not be excluded",
            isExcluded(uriName("competitor.example"), uriName("https://other.example./")));
        assertFalse("trailing-dot DNS name on another host must not be excluded",
            isExcluded(dnsName("bank.com"), dnsName("notbank.com.")));
        assertFalse("trailing-dot email on another host must not be permitted",
            isPermitted(emailName("bank.com"), emailName("ceo@notbank.com.")));
    }

    /**
     * Only the single root-label dot of RFC 1034 sec. 3.1 is canonicalized away. A host carrying any
     * other empty label - a second trailing dot, a doubled dot, a leading dot - is not a name
     * RFC 5280 sec. 4.2.1.6 admits, and stripping the extra dots would decide on the caller's behalf
     * that "example.com.." names example.com. It is refused instead, in both directions, so it can
     * neither escape an excluded subtree nor be admitted by a permitted one.
     */
    public void testEmptyLabelRefused()
        throws Exception
    {
        // dNSName: every shape of empty label is refused, whichever domain the name appears to carry.
        assertTrue("two trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com..")));
        assertTrue("three trailing dots must be refused",
            isExcluded(dnsName("example.com"), dnsName("example.com...")));
        assertTrue("a doubled inner dot must be refused",
            isExcluded(dnsName("example.com"), dnsName("foo..example.com")));
        assertTrue("a leading dot must be refused",
            isExcluded(dnsName("example.com"), dnsName(".example.com")));
        assertTrue("a sibling domain with an empty label must be refused too",
            isExcluded(dnsName("example.com"), dnsName("notexample.com..")));

        // the permitted direction refuses it as well, so canonicalizing has not admitted anything new.
        assertFalse("an empty label must not be permitted",
            isPermitted(dnsName("example.com"), dnsName("example.com..")));
        assertTrue("a well-formed name is still permitted",
            isPermitted(dnsName("example.com"), dnsName("example.com.")));

        // rfc822Name and URI share the guard, applied to the host.
        assertTrue("two trailing dots on a mail host must be refused",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com..")));
        assertTrue("a doubled inner dot on a mail host must be refused",
            isExcluded(emailName(".bank.com"), emailName("ceo@mail..bank.com")));
        assertFalse("an empty label on a mail host must not be permitted",
            isPermitted(emailName("bank.com"), emailName("ceo@bank.com..")));
        assertTrue("two trailing dots on a URI host must be refused",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example../")));
        assertFalse("an empty label on a URI host must not be permitted",
            isPermitted(uriName("competitor.example"), uriName("https://competitor.example../")));

        // the guard is scoped to the host: a quoted local part may legally carry a doubled dot.
        assertTrue("a doubled dot in a quoted local part must not be refused, and the host still matches",
            isExcluded(emailName("bank.com"), emailName("\"a..b\"@bank.com")));
        assertTrue("a doubled dot in a quoted local part must still be permitted",
            isPermitted(emailName("bank.com"), emailName("\"a..b\"@bank.com")));

        // a bare "." is the root label, not an empty one, and is left alone.
        assertFalse("a bare root label must not be refused", isExcluded(dnsName("example.com"), dnsName(".")));

        // nothing is refused where no constraint of that type is in force.
        assertFalse("an empty label is immaterial with no dNSName constraint",
            isExcluded(emailName("bank.com"), dnsName("example.com..")));
        assertTrue("an empty label is immaterial with no dNSName constraint",
            isPermitted(emailName("bank.com"), dnsName("example.com..")));
    }

    /**
     * End to end: a name-constrained CA permitted only C=US,O=TrustedOrg must not be able to vouch
     * for a certificate whose subject prepends RDNs ahead of the permitted sequence. The subject
     * under test is carried by the sub CA issued by the constrained CA, which the reviewer checks
     * against the inherited name constraints.
     */
    public void testPKIXCertPathReviewerDirectoryNamePrefix()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        NameConstraints trustedOrgOnly = new NameConstraints(
            new GeneralSubtree[]{ new GeneralSubtree(directoryName("C=US,O=TrustedOrg")) }, null);

        PKIXCertPathReviewer badReviewer = review(createConstrainedChain(trustedOrgOnly,
            new X500Name("C=FR,O=Attacker,C=US,O=TrustedOrg,CN=NC DN Sub CA"), null));
        assertFalse("reviewer accepted a sub CA with RDNs prepended ahead of the permitted subtree: "
            + describeErrors(badReviewer), badReviewer.isValidCertPath());
        assertTrue("prepended-RDN subject of the sub CA not reported: " + describeErrors(badReviewer),
            containsError(badReviewer.getErrors(CA2_INDEX), NOT_PERMITTED_DN_ERROR));

        PKIXCertPathReviewer goodReviewer = review(createConstrainedChain(trustedOrgOnly,
            new X500Name("C=US,O=TrustedOrg,CN=NC DN Sub CA"), null));
        assertTrue("reviewer rejected a compliant sub CA: " + describeErrors(goodReviewer),
            goodReviewer.isValidCertPath());
    }

    /**
     * End to end: a trailing dot (or an extra empty label) on a subject alternative name must not
     * let it escape the excluded subtrees of its name-constrained issuer.
     */
    public void testPKIXCertPathReviewerTrailingDotExcluded()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        NameConstraints excluded = new NameConstraints(null, new GeneralSubtree[]{
            new GeneralSubtree(emailName("bank.com")),
            new GeneralSubtree(uriName("competitor.example")),
            new GeneralSubtree(dnsName("bank.com")) });

        GeneralName[] evasions = new GeneralName[]{
            emailName("ceo@bank.com."),
            uriName("https://competitor.example./"),
            dnsName("bank.com."),
            dnsName("bank.com..") };

        for (int i = 0; i != evasions.length; i++)
        {
            PKIXCertPathReviewer badReviewer = review(createConstrainedChain(excluded,
                new X500Name("CN=NC Trailing Dot Sub CA"), new GeneralNames(evasions[i])));
            assertFalse("reviewer accepted excluded name " + evasions[i] + ": " + describeErrors(badReviewer),
                badReviewer.isValidCertPath());
            assertTrue("excluded name " + evasions[i] + " of the sub CA not reported: "
                + describeErrors(badReviewer), containsError(badReviewer.getErrors(CA2_INDEX), NOT_PERMITTED_NAME_ERROR));
        }

        PKIXCertPathReviewer goodReviewer = review(createConstrainedChain(excluded,
            new X500Name("CN=NC Trailing Dot Sub CA"), new GeneralNames(new GeneralName[]{
                emailName("ceo@other.com."), uriName("https://other.example./"), dnsName("other.com.") })));
        assertTrue("reviewer rejected a compliant sub CA: " + describeErrors(goodReviewer),
            goodReviewer.isValidCertPath());
    }

    private static boolean isPermitted(GeneralName constraint, GeneralName name)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();

        validator.intersectPermittedSubtree(new GeneralSubtree(constraint));

        try
        {
            validator.checkPermitted(name);
            return true;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return false;
        }
    }

    private static boolean isExcluded(GeneralName constraint, GeneralName name)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();

        validator.addExcludedSubtree(new GeneralSubtree(constraint));

        try
        {
            validator.checkExcluded(name);
            return false;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return true;
        }
    }

    private static GeneralName directoryName(String name)
    {
        return new GeneralName(GeneralName.directoryName, new X500Name(name));
    }

    private static GeneralName emailName(String name)
    {
        return new GeneralName(GeneralName.rfc822Name, name);
    }

    private static GeneralName uriName(String name)
    {
        return new GeneralName(GeneralName.uniformResourceIdentifier, name);
    }

    private static GeneralName dnsName(String name)
    {
        return new GeneralName(GeneralName.dNSName, name);
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

    /**
     * Build root -&gt; constrained CA -&gt; sub CA -&gt; leaf, returned in path order (leaf first, root
     * last). The constrained CA carries nameConstraints, and the sub CA carries the subject and
     * subject alternative names under test, so they are checked against those constraints at
     * CA2_INDEX. The leaf is kept inside every constraint the tests use.
     */
    private static X509Certificate[] createConstrainedChain(NameConstraints nameConstraints, X500Name subCaName,
        GeneralNames subCaAltNames)
        throws Exception
    {
        X509Certificate root = makeRoot();
        X509Certificate constrainedCa = makeCertificate(root, getRootKp().getPrivate(), getCa1Kp().getPublic(),
            principal(new X500Name("C=US,O=TrustedOrg,CN=NC Constrained CA")), true, nameConstraints, null);
        X509Certificate subCa = makeCertificate(constrainedCa, getCa1Kp().getPrivate(), getCa2Kp().getPublic(),
            principal(subCaName), true, null, subCaAltNames);
        X509Certificate leaf = makeCertificate(subCa, getCa2Kp().getPrivate(), getLeafKp().getPublic(),
            principal(new X500Name("C=US,O=TrustedOrg,CN=NC Leaf")), false, null, null);

        return new X509Certificate[] { leaf, subCa, constrainedCa, root };
    }

    /**
     * The X500Principal with the same encoding as name, so the RDN order written in name is the
     * order the certificate carries.
     */
    private static X500Principal principal(X500Name name)
        throws IOException
    {
        return new X500Principal(name.getEncoded());
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
        return makeCertificate(issuer, issuerKey, subjectKey, new X500Principal(subject), isCA, nameConstraints,
            subjectAltNames);
    }

    private static X509Certificate makeCertificate(X509Certificate issuer, PrivateKey issuerKey, PublicKey subjectKey,
        X500Principal subject, boolean isCA, NameConstraints nameConstraints, GeneralNames subjectAltNames)
        throws Exception
    {
        long now = System.currentTimeMillis();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            issuer.getSubjectX500Principal(),
            allocateSerialNumber(),
            new Date(now - 1000L * 60),
            new Date(now + (1000L * 60 * 60 * 24 * 100)),
            subject,
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
