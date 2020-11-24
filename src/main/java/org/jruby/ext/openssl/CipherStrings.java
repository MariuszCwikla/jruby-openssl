/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2008 Ola Bini <ola.bini@gmail.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.jruby.ext.openssl.SSL.SSL3_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_1_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_2_VERSION;
import static org.jruby.ext.openssl.SSL.TLS1_3_VERSION;

/**
 *
 * @author <a href="mailto:ola.bini@gmail.com">Ola Bini</a>
 */
public class CipherStrings {

    public final static String SSL2_TXT_DES_64_CFB64_WITH_MD5_1 = "DES-CFB-M1";
    public final static String SSL2_TXT_NULL_WITH_MD5 = "NULL-MD5";
    public final static String SSL2_TXT_RC4_128_WITH_MD5 = "RC4-MD5";
    public final static String SSL2_TXT_RC4_128_EXPORT40_WITH_MD5 = "EXP-RC4-MD5";
    public final static String SSL2_TXT_RC2_128_CBC_WITH_MD5 = "RC2-CBC-MD5";
    public final static String SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = "EXP-RC2-CBC-MD5";
    public final static String SSL2_TXT_IDEA_128_CBC_WITH_MD5 = "IDEA-CBC-MD5";
    public final static String SSL2_TXT_DES_64_CBC_WITH_MD5 = "DES-CBC-MD5";
    public final static String SSL2_TXT_DES_64_CBC_WITH_SHA = "DES-CBC-SHA";
    public final static String SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5 = "DES-CBC3-MD5";
    public final static String SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA = "DES-CBC3-SHA";
    public final static String SSL2_TXT_RC4_64_WITH_MD5 = "RC4-64-MD5";
    public final static String SSL2_TXT_NULL = "NULL";

    public final static String SSL3_TXT_EDH_DSS_DES_40_CBC_SHA = "EXP-EDH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_DSS_DES_64_CBC_SHA = "EDH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA = "EDH-DSS-DES-CBC3-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_40_CBC_SHA = "EXP-EDH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_64_CBC_SHA = "EDH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA = "EDH-RSA-DES-CBC3-SHA";
    public final static String SSL3_TXT_ADH_RC4_40_MD5 = "EXP-ADH-RC4-MD5";
    public final static String SSL3_TXT_ADH_RC4_128_MD5 = "ADH-RC4-MD5";
    public final static String SSL3_TXT_ADH_DES_40_CBC_SHA = "EXP-ADH-DES-CBC-SHA";
    public final static String SSL3_TXT_ADH_DES_64_CBC_SHA = "ADH-DES-CBC-SHA";
    public final static String SSL3_TXT_ADH_DES_192_CBC_SHA = "ADH-DES-CBC3-SHA";
    public final static String SSL3_TXT_FZA_DMS_NULL_SHA = "FZA-NULL-SHA";
    public final static String SSL3_TXT_FZA_DMS_FZA_SHA = "FZA-FZA-CBC-SHA";
    public final static String SSL3_TXT_FZA_DMS_RC4_SHA = "FZA-RC4-SHA";
    public final static String SSL3_TXT_KRB5_DES_64_CBC_SHA = "KRB5-DES-CBC-SHA";
    public final static String SSL3_TXT_KRB5_DES_192_CBC3_SHA = "KRB5-DES-CBC3-SHA";
    public final static String SSL3_TXT_KRB5_RC4_128_SHA = "KRB5-RC4-SHA";
    public final static String SSL3_TXT_KRB5_IDEA_128_CBC_SHA = "KRB5-IDEA-CBC-SHA";
    public final static String SSL3_TXT_KRB5_DES_64_CBC_MD5 = "KRB5-DES-CBC-MD5";
    public final static String SSL3_TXT_KRB5_DES_192_CBC3_MD5 = "KRB5-DES-CBC3-MD5";
    public final static String SSL3_TXT_KRB5_RC4_128_MD5 = "KRB5-RC4-MD5";
    public final static String SSL3_TXT_KRB5_IDEA_128_CBC_MD5 = "KRB5-IDEA-CBC-MD5";
    public final static String SSL3_TXT_KRB5_DES_40_CBC_SHA = "EXP-KRB5-DES-CBC-SHA";
    public final static String SSL3_TXT_KRB5_RC2_40_CBC_SHA = "EXP-KRB5-RC2-CBC-SHA";
    public final static String SSL3_TXT_KRB5_RC4_40_SHA = "EXP-KRB5-RC4-SHA";
    public final static String SSL3_TXT_KRB5_DES_40_CBC_MD5 = "EXP-KRB5-DES-CBC-MD5";
    public final static String SSL3_TXT_KRB5_RC2_40_CBC_MD5 = "EXP-KRB5-RC2-CBC-MD5";
    public final static String SSL3_TXT_KRB5_RC4_40_MD5 = "EXP-KRB5-RC4-MD5";

    public final static String SSL_TXT_NULL_WITH_MD5 = SSL2_TXT_NULL_WITH_MD5;
    public final static String SSL_TXT_RC4_128_WITH_MD5 = SSL2_TXT_RC4_128_WITH_MD5;
    public final static String SSL_TXT_RC4_128_EXPORT40_WITH_MD5 = SSL2_TXT_RC4_128_EXPORT40_WITH_MD5;
    public final static String SSL_TXT_RC2_128_CBC_WITH_MD5 = SSL2_TXT_RC2_128_CBC_WITH_MD5;
    public final static String SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 = SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5;
    public final static String SSL_TXT_IDEA_128_CBC_WITH_MD5 = SSL2_TXT_IDEA_128_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_64_CBC_WITH_MD5 = SSL2_TXT_DES_64_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_64_CBC_WITH_SHA = SSL2_TXT_DES_64_CBC_WITH_SHA;
    public final static String SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 = SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5;
    public final static String SSL_TXT_DES_192_EDE3_CBC_WITH_SHA = SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA;

    public final static String SSL_TXT_KRB5_DES_64_CBC_SHA = SSL3_TXT_KRB5_DES_64_CBC_SHA;
    public final static String SSL_TXT_KRB5_DES_192_CBC3_SHA = SSL3_TXT_KRB5_DES_192_CBC3_SHA;
    public final static String SSL_TXT_KRB5_RC4_128_SHA = SSL3_TXT_KRB5_RC4_128_SHA;
    public final static String SSL_TXT_KRB5_IDEA_128_CBC_SHA = SSL3_TXT_KRB5_IDEA_128_CBC_SHA;
    public final static String SSL_TXT_KRB5_DES_64_CBC_MD5 = SSL3_TXT_KRB5_DES_64_CBC_MD5;
    public final static String SSL_TXT_KRB5_DES_192_CBC3_MD5 = SSL3_TXT_KRB5_DES_192_CBC3_MD5;
    public final static String SSL_TXT_KRB5_RC4_128_MD5 = SSL3_TXT_KRB5_RC4_128_MD5;
    public final static String SSL_TXT_KRB5_IDEA_128_CBC_MD5 = SSL3_TXT_KRB5_IDEA_128_CBC_MD5;

    public final static String SSL_TXT_KRB5_DES_40_CBC_SHA = SSL3_TXT_KRB5_DES_40_CBC_SHA;
    public final static String SSL_TXT_KRB5_RC2_40_CBC_SHA = SSL3_TXT_KRB5_RC2_40_CBC_SHA;
    public final static String SSL_TXT_KRB5_RC4_40_SHA = SSL3_TXT_KRB5_RC4_40_SHA;
    public final static String SSL_TXT_KRB5_DES_40_CBC_MD5 = SSL3_TXT_KRB5_DES_40_CBC_MD5;
    public final static String SSL_TXT_KRB5_RC2_40_CBC_MD5 = SSL3_TXT_KRB5_RC2_40_CBC_MD5;
    public final static String SSL_TXT_KRB5_RC4_40_MD5 = SSL3_TXT_KRB5_RC4_40_MD5;

    public final static String SSL_TXT_LOW = "LOW";
    public final static String SSL_TXT_MEDIUM = "MEDIUM";
    public final static String SSL_TXT_HIGH = "HIGH";
    public final static String SSL_TXT_FIPS = "FIPS";
    public final static String SSL_TXT_kFZA = "kFZA";
    public final static String SSL_TXT_aFZA = "aFZA";
    public final static String SSL_TXT_eFZA = "eFZA";
    public final static String SSL_TXT_FZA = "FZA";

    public final static String SSL_TXT_aNULL = "aNULL";
    public final static String SSL_TXT_eNULL = "eNULL";
    public final static String SSL_TXT_NULL = "NULL";

//    public final static String SSL_TXT_kKRB5 = "kKRB5";
    public final static String SSL_TXT_aKRB5 = "aKRB5";
    public final static String SSL_TXT_KRB5 = "KRB5";

    public final static String SSL_TXT_kRSA = "kRSA";
    public final static String SSL_TXT_kDHr = "kDHr";
    public final static String SSL_TXT_kDHd = "kDHd";
    public final static String SSL_TXT_kEDH = "kEDH";
    public final static String SSL_TXT_kDHE = "kDHE";

    public final static String SSL_TXT_kECDHr         = "kECDHr";/* this cipher class has been removed */
    public final static String SSL_TXT_kECDHe         = "kECDHe";/* this cipher class has been removed */
    public final static String SSL_TXT_kECDH          = "kECDH";/* this cipher class has been removed */
    public final static String SSL_TXT_kEECDH         = "kEECDH";/* alias for kECDHE */
    public final static String SSL_TXT_kECDHE         = "kECDHE";
    public final static String SSL_TXT_kPSK           = "kPSK";
    public final static String SSL_TXT_kRSAPSK        = "kRSAPSK";
    public final static String SSL_TXT_kECDHEPSK      = "kECDHEPSK";
    public final static String SSL_TXT_kDHEPSK        = "kDHEPSK";
    public final static String SSL_TXT_kGOST          = "kGOST";
    public final static String SSL_TXT_kSRP           = "kSRP";

    public final static String SSL_TXT_aRSA = "aRSA";
    public final static String SSL_TXT_aDSS = "aDSS";
    public final static String SSL_TXT_aDH = "aDH";/* this cipher class has been removed */
    public final static String SSL_TXT_aECDH           = "aECDH";/* this cipher class has been removed */
    public final static String SSL_TXT_aECDSA          = "aECDSA";
    public final static String SSL_TXT_aPSK            = "aPSK";
    public final static String SSL_TXT_aGOST94         = "aGOST94";
    public final static String SSL_TXT_aGOST01         = "aGOST01";
    public final static String SSL_TXT_aGOST12         = "aGOST12";
    public final static String SSL_TXT_aGOST           = "aGOST";
    public final static String SSL_TXT_aSRP            = "aSRP";
    public final static String SSL_TXT_DSS = "DSS";
    public final static String SSL_TXT_DH = "DH";
    public final static String SSL_TXT_DHE = "DHE";
    public final static String SSL_TXT_EDH = "EDH";
    public final static String SSL_TXT_ADH = "ADH";
    public final static String SSL_TXT_RSA = "RSA";

    public final static String SSL_TXT_ECDH            = "ECDH";
    public final static String SSL_TXT_EECDH           = "EECDH";/* alias for ECDHE" */
    public final static String SSL_TXT_ECDHE           = "ECDHE";/* same as "kECDHE:-AECDH" */
    public final static String SSL_TXT_AECDH           = "AECDH";
    public final static String SSL_TXT_ECDSA           = "ECDSA";
    public final static String SSL_TXT_PSK             = "PSK";
    public final static String SSL_TXT_SRP             = "SRP";

    
    public final static String SSL_TXT_DES = "DES";
    public final static String SSL_TXT_3DES = "3DES";
    public final static String SSL_TXT_RC4 = "RC4";
    public final static String SSL_TXT_RC2 = "RC2";
    public final static String SSL_TXT_IDEA = "IDEA";
    public final static String SSL_TXT_SEED           = "SEED";
    public final static String SSL_TXT_AES128         = "AES128";
    public final static String SSL_TXT_AES256         = "AES256";
    public final static String SSL_TXT_AES            = "AES";
    public final static String SSL_TXT_AES_GCM        = "AESGCM";
    public final static String SSL_TXT_AES_CCM        = "AESCCM";
    public final static String SSL_TXT_AES_CCM_8      = "AESCCM8";
    public final static String SSL_TXT_CAMELLIA128    = "CAMELLIA128";
    public final static String SSL_TXT_CAMELLIA256    = "CAMELLIA256";
    public final static String SSL_TXT_CAMELLIA       = "CAMELLIA";
    public final static String SSL_TXT_CHACHA20       = "CHACHA20";
    public final static String SSL_TXT_GOST           = "GOST89";
    public final static String SSL_TXT_ARIA           = "ARIA";
    public final static String SSL_TXT_ARIA_GCM       = "ARIAGCM";
    public final static String SSL_TXT_ARIA128        = "ARIA128";
    public final static String SSL_TXT_ARIA256        = "ARIA256";

    public final static String SSL_TXT_MD5 = "MD5";
    public final static String SSL_TXT_SHA1 = "SHA1";
    public final static String SSL_TXT_SHA = "SHA";
    public final static String SSL_TXT_GOST94          = "GOST94";
    public final static String SSL_TXT_GOST89MAC       = "GOST89MAC";
    public final static String SSL_TXT_GOST12          = "GOST12";
    public final static String SSL_TXT_GOST89MAC12     = "GOST89MAC12";
    public final static String SSL_TXT_SHA256          = "SHA256";
    public final static String SSL_TXT_SHA384          = "SHA384";


    public final static String SSL_TXT_EXP = "EXP";
    public final static String SSL_TXT_EXPORT = "EXPORT";
    public final static String SSL_TXT_EXP40 = "EXPORT40";
    public final static String SSL_TXT_EXP56 = "EXPORT56";
    public final static String SSL_TXT_SSLV2 = "SSLv2";
    public final static String SSL_TXT_SSLV3 = "SSLv3";
    public final static String SSL_TXT_TLSV1 = "TLSv1";
    public final static String SSL_TXT_TLSV1_1 = "TLSv1.1";
    public final static String SSL_TXT_TLSV1_2 = "TLSv1.2";
    public final static String SSL_TXT_ALL = "ALL";
    public final static String SSL_TXT_ECC = "ECCdraft";

    public final static String SSL_TXT_CMPALL = "COMPLEMENTOFALL";
    public final static String SSL_TXT_CMPDEF = "COMPLEMENTOFDEFAULT";

    // "ALL:!aNULL:!eNULL:!SSLv2" is for OpenSSL 1.0.0 GA
    public final static String SSL_DEFAULT_CIPHER_LIST = "AES:ALL:!aNULL:!eNULL:+RC4:@STRENGTH";

    public final static long SSL_MKEY_MASK = 0x000000FFL;
    public final static long SSL_kRSA = 0x00000001L;
    public final static long SSL_kDHE = 0x00000002L;
    public final static long SSL_kEDH = SSL_kDHE;       //synonym
    public final static long SSL_kECDHE              = 0x00000004;
    public final static long SSL_kEECDH              = SSL_kECDHE;       //synonym
    public final static long SSL_kPSK                = 0x00000008;
    public final static long SSL_kGOST               = 0x00000010;
    public final static long SSL_kSRP                = 0x00000020;

    public final static long SSL_kRSAPSK             = 0x00000040;
    public final static long SSL_kECDHEPSK           = 0x00000080;
    public final static long SSL_kDHEPSK             = 0x00000100;

    /* all PSK */

    public final static long SSL_PSK     = (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK);

    /* Any appropriate key exchange algorithm (for TLS 1.3 ciphersuites) */
    public final static long SSL_kANY                = 0x00000000;

    public final static long SSL_aRSA                = 0x00000001;
    public final static long SSL_aDSS                = 0x00000002;
    public final static long SSL_aNULL               = 0x00000004;
    public final static long SSL_aECDSA              = 0x00000008;
    public final static long SSL_aPSK                = 0x00000010;
    public final static long SSL_aGOST01             = 0x00000020;
    public final static long SSL_aSRP                = 0x00000040;
    public final static long SSL_aGOST12             = 0x00000080;
    /* Any appropriate signature auth (for TLS 1.3 ciphersuites) */
    public final static long SSL_aANY                = 0x00000000;
    /* All bits requiring a certificate */
    public final static long SSL_aCERT = (SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12);

    public final static long SSL_kDHr = 0x00000002L;
    public final static long SSL_kDHd = 0x00000004L;
    public final static long SSL_kFZA = 0x00000008L;
    public final static long SSL_kKRB5 = 0x00000020L;
    public final static long SSL_kECDH = 0x00000040L;
//    public final static long SSL_kECDHE = 0x00000080L;
//    public final static long SSL_aNULL = 0x00000800L;
    public final static long SSL_AUTH_MASK = 0x00007F00L;
    public final static long SSL_EDH = (SSL_kEDH|(SSL_AUTH_MASK^SSL_aNULL));
//    public final static long SSL_aRSA = 0x00000100L;
//    public final static long SSL_aDSS = 0x00000200L;
    public final static long SSL_DSS = SSL_aDSS;
    public final static long SSL_aFZA = 0x00000400L;
    public final static long SSL_aDH = 0x00001000L;
    public final static long SSL_aKRB5 = 0x00002000L;
//    public final static long SSL_aECDSA = 0x00004000L;
//    public final static long SSL_eNULL = 0x00200000L;
    public final static long SSL_eFZA = 0x00100000L;
    @Deprecated public final static long SSL_NULL = 0x00000020;
    public final static long SSL_ADH = (SSL_kEDH|SSL_aNULL);
    public final static long SSL_RSA = (SSL_kRSA|SSL_aRSA);
    public final static long SSL_DH = (SSL_kDHr|SSL_kDHd|SSL_kEDH);
    public final static long SSL_ECDH = (SSL_kECDH|SSL_kECDHE);
    public final static long SSL_FZA = (SSL_aFZA|SSL_kFZA|SSL_eFZA);
    public final static long SSL_KRB5 = (SSL_kKRB5|SSL_aKRB5);
    public final static long SSL_ENC_MASK = 0x043F8000L;
//    public final static long SSL_DES = 0x00008000L;
//    public final static long SSL_3DES = 0x00010000L;
//    public final static long SSL_RC4 = 0x00020000L;
//    public final static long SSL_RC2 = 0x00040000L;
//    public final static long SSL_IDEA = 0x00080000L;
//    public final static long SSL_AES = 0x04000000L;
    public final static long SSL_MAC_MASK = 0x00c00000L;
//    public final static long SSL_MD5 = 0x00400000L;
//    public final static long SSL_SHA1 = 0x00800000L;
    @Deprecated public final static long SSL_SHA = 0x00000002;
    public final static long SSL_SSL_MASK = 0x03000000L;
    public final static long SSL_SSLV2 = 0x01000000L;
    public final static long SSL_SSLV3 = 0x02000000L;
    public final static long SSL_TLSV1 = SSL_SSLV3;
    public final static long SSL_EXP_MASK = 0x00000003L;
    public final static long SSL_NOT_EXP = 0x00000001L;
    public final static long SSL_EXPORT = 0x00000002L;
//    public final static long SSL_STRONG_MASK = 0x000000fcL;
//    public final static long SSL_STRONG_NONE = 0x00000004L;
    public final static long SSL_EXP40 = 0x00000008L;
    public final static long SSL_MICRO = (SSL_EXP40);
    public final static long SSL_EXP56 = 0x00000010L;
    public final static long SSL_MINI = (SSL_EXP56);
//    public final static long SSL_LOW = 0x00000020L;
//    public final static long SSL_MEDIUM = 0x00000040L;
//    public final static long SSL_HIGH = 0x00000080L;
    public final static long SSL_ALL = 0xffffffffL;
    public final static long SSL_ALL_CIPHERS = (SSL_MKEY_MASK|SSL_AUTH_MASK|SSL_ENC_MASK|SSL_MAC_MASK);
    //public final static long SSL_ALL_STRENGTHS = (SSL_EXP_MASK|SSL_STRONG_MASK);
    @Deprecated public final static long SSL_ALL_STRENGTHS = (SSL_EXP_MASK|0x0000001F);
    public final static long SSL_PKEY_RSA_ENC = 0;
    public final static long SSL_PKEY_RSA_SIGN = 1;
    public final static long SSL_PKEY_DSA_SIGN = 2;
    public final static long SSL_PKEY_DH_RSA = 3;
    public final static long SSL_PKEY_DH_DSA = 4;
    public final static long SSL_PKEY_ECC = 5;
    public final static long SSL_PKEY_NUM = 6;
    
/* OpenSSL 1.1.1 */
    public static final long SSL_DES                 = 0x00000001;
    public static final long SSL_3DES                = 0x00000002;
    public static final long SSL_RC4                 = 0x00000004;
    public static final long SSL_RC2                 = 0x00000008;
    public static final long SSL_IDEA                = 0x00000010;
    public static final long SSL_eNULL               = 0x00000020;
    public static final long SSL_AES128              = 0x00000040;
    public static final long SSL_AES256              = 0x00000080;
    public static final long SSL_CAMELLIA128         = 0x00000100;
    public static final long SSL_CAMELLIA256         = 0x00000200;
    public static final long SSL_eGOST2814789CNT     = 0x00000400;
    public static final long SSL_SEED                = 0x00000800;
    public static final long SSL_AES128GCM           = 0x00001000;
    public static final long SSL_AES256GCM           = 0x00002000;
    public static final long SSL_AES128CCM           = 0x00004000;
    public static final long SSL_AES256CCM           = 0x00008000;
    public static final long SSL_AES128CCM8          = 0x00010000;
    public static final long SSL_AES256CCM8          = 0x00020000;
    public static final long SSL_eGOST2814789CNT12   = 0x00040000;
    public static final long SSL_CHACHA20POLY1305    = 0x00080000;
    public static final long SSL_ARIA128GCM          = 0x00100000;
    public static final long SSL_ARIA256GCM          = 0x00200000;

    public static final long SSL_AESGCM              = (SSL_AES128GCM | SSL_AES256GCM);
    public static final long SSL_AESCCM              = (SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8);
    public static final long SSL_AES                 = (SSL_AES128|SSL_AES256|SSL_AESGCM|SSL_AESCCM);
    public static final long SSL_CAMELLIA            = (SSL_CAMELLIA128|SSL_CAMELLIA256);
    public static final long SSL_CHACHA20            = (SSL_CHACHA20POLY1305);
    public static final long SSL_ARIAGCM             = (SSL_ARIA128GCM | SSL_ARIA256GCM);
    public static final long SSL_ARIA                = (SSL_ARIAGCM);

    /* Bits for algorithm_mac (symmetric authentication) */

    public static final long SSL_MD5                 = 0x00000001;
    public static final long SSL_SHA1                = 0x00000002;
    public static final long SSL_GOST94              = 0x00000004;
    public static final long SSL_GOST89MAC           = 0x00000008;
    public static final long SSL_SHA256              = 0x00000010;
    public static final long SSL_SHA384              = 0x00000020;
    /* Not a real MAC, just an indication it is part of cipher */
    public static final long SSL_AEAD                = 0x00000040;
    public static final long SSL_GOST12_256          = 0x00000080;
    public static final long SSL_GOST89MAC12         = 0x00000100;
    public static final long SSL_GOST12_512          = 0x00000200;
    
    
/*
 * 
 * When adding new digest in the ssl_ciph.c and increment SSL_MD_NUM_IDX make
 * sure to update this constant too
*/ 

    public final static long  SSL_MD_MD5_IDX = 0;
    public final static long  SSL_MD_SHA1_IDX = 1;
    public final static long  SSL_MD_GOST94_IDX = 2;
    public final static long  SSL_MD_GOST89MAC_IDX = 3;
    public final static long  SSL_MD_SHA256_IDX = 4;
    public final static long  SSL_MD_SHA384_IDX = 5;
    public final static long  SSL_MD_GOST12_256_IDX = 6;
    public final static long  SSL_MD_GOST89MAC12_IDX = 7;
    public final static long  SSL_MD_GOST12_512_IDX = 8;
    public final static long  SSL_MD_MD5_SHA1_IDX = 9;
    public final static long  SSL_MD_SHA224_IDX = 10;
    public final static long  SSL_MD_SHA512_IDX = 11;
    public final static long  SSL_MAX_DIGEST = 12;

/* Bits for algorithm2 (handshake digests and other extra flags)

/* Bits 0-7 are handshake MAC */ 
    public final static long SSL_HANDSHAKE_MAC_MASK  = 0xFF;
    public final static long SSL_HANDSHAKE_MAC_MD5_SHA1 = SSL_MD_MD5_SHA1_IDX;
    public final static long SSL_HANDSHAKE_MAC_SHA256 = SSL_MD_SHA256_IDX;
    public final static long SSL_HANDSHAKE_MAC_SHA384 = SSL_MD_SHA384_IDX;
    public final static long SSL_HANDSHAKE_MAC_GOST94 = SSL_MD_GOST94_IDX;
    public final static long SSL_HANDSHAKE_MAC_GOST12_256 = SSL_MD_GOST12_256_IDX;
    public final static long SSL_HANDSHAKE_MAC_GOST12_512 = SSL_MD_GOST12_512_IDX;
    public final static long SSL_HANDSHAKE_MAC_DEFAULT  = SSL_HANDSHAKE_MAC_MD5_SHA1;

    /* Bits 8-15 bits are PRF*/
    public final static long  TLS1_PRF_DGST_SHIFT = 8;
    public final static long  TLS1_PRF_SHA1_MD5 = (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF_SHA256 = (SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF_SHA384 = (SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF_GOST94 = (SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF_GOST12_256 = (SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF_GOST12_512 = (SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT);
    public final static long  TLS1_PRF            = (SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT);

    public static final long TLS1_STREAM_MAC = 0x10000;

    public static final long SSL_STRONG_MASK         = 0x0000001F;
    public static final long SSL_DEFAULT_MASK        = 0x00000020;

    public static final long SSL_STRONG_NONE         = 0x00000001;
    public static final long SSL_LOW                 = 0x00000002;
    public static final long SSL_MEDIUM              = 0x00000004;
    public static final long SSL_HIGH                = 0x00000008;
    public static final long SSL_FIPS                = 0x00000010;
    public static final long SSL_NOT_DEFAULT         = 0x00000020;
    
    
/* end of open ssl 1.1.1*/

/* ssl3.h */
    public final static long  SSL3_CK_SCSV                            = 0x030000FF;

    /*
     * Signalling cipher suite value from draft-ietf-tls-downgrade-scsv-00
     * (TLS_FALLBACK_SCSV)
     */
    public final static long  SSL3_CK_FALLBACK_SCSV                   = 0x03005600;

    public final static long  SSL3_CK_RSA_NULL_MD5                    = 0x03000001;
    public final static long  SSL3_CK_RSA_NULL_SHA                    = 0x03000002;
    public final static long  SSL3_CK_RSA_RC4_40_MD5                  = 0x03000003;
    public final static long  SSL3_CK_RSA_RC4_128_MD5                 = 0x03000004;
    public final static long  SSL3_CK_RSA_RC4_128_SHA                 = 0x03000005;
    public final static long  SSL3_CK_RSA_RC2_40_MD5                  = 0x03000006;
    public final static long  SSL3_CK_RSA_IDEA_128_SHA                = 0x03000007;
    public final static long  SSL3_CK_RSA_DES_40_CBC_SHA              = 0x03000008;
    public final static long  SSL3_CK_RSA_DES_64_CBC_SHA              = 0x03000009;
    public final static long  SSL3_CK_RSA_DES_192_CBC3_SHA            = 0x0300000A;

    public final static long  SSL3_CK_DH_DSS_DES_40_CBC_SHA           = 0x0300000B;
    public final static long  SSL3_CK_DH_DSS_DES_64_CBC_SHA           = 0x0300000C;
    public final static long  SSL3_CK_DH_DSS_DES_192_CBC3_SHA         = 0x0300000D;
    public final static long  SSL3_CK_DH_RSA_DES_40_CBC_SHA           = 0x0300000E;
    public final static long  SSL3_CK_DH_RSA_DES_64_CBC_SHA           = 0x0300000F;
    public final static long  SSL3_CK_DH_RSA_DES_192_CBC3_SHA         = 0x03000010;

    public final static long  SSL3_CK_DHE_DSS_DES_40_CBC_SHA          = 0x03000011;
    public final static long  SSL3_CK_EDH_DSS_DES_40_CBC_SHA          = SSL3_CK_DHE_DSS_DES_40_CBC_SHA;
    public final static long  SSL3_CK_DHE_DSS_DES_64_CBC_SHA          = 0x03000012;
    public final static long  SSL3_CK_EDH_DSS_DES_64_CBC_SHA          = SSL3_CK_DHE_DSS_DES_64_CBC_SHA;
    public final static long  SSL3_CK_DHE_DSS_DES_192_CBC3_SHA        = 0x03000013;
    public final static long  SSL3_CK_EDH_DSS_DES_192_CBC3_SHA        = SSL3_CK_DHE_DSS_DES_192_CBC3_SHA;
    public final static long  SSL3_CK_DHE_RSA_DES_40_CBC_SHA          = 0x03000014;
    public final static long  SSL3_CK_EDH_RSA_DES_40_CBC_SHA          = SSL3_CK_DHE_RSA_DES_40_CBC_SHA;
    public final static long  SSL3_CK_DHE_RSA_DES_64_CBC_SHA          = 0x03000015;
    public final static long  SSL3_CK_EDH_RSA_DES_64_CBC_SHA          = SSL3_CK_DHE_RSA_DES_64_CBC_SHA;
    public final static long  SSL3_CK_DHE_RSA_DES_192_CBC3_SHA        = 0x03000016;
    public final static long  SSL3_CK_EDH_RSA_DES_192_CBC3_SHA        = SSL3_CK_DHE_RSA_DES_192_CBC3_SHA;

    public final static long  SSL3_CK_ADH_RC4_40_MD5                  = 0x03000017;
    public final static long  SSL3_CK_ADH_RC4_128_MD5                 = 0x03000018;
    public final static long  SSL3_CK_ADH_DES_40_CBC_SHA              = 0x03000019;
    public final static long  SSL3_CK_ADH_DES_64_CBC_SHA              = 0x0300001A;
    public final static long  SSL3_CK_ADH_DES_192_CBC_SHA             = 0x0300001B;

    
//    public final static long SSL3_CK_RSA_NULL_MD5 = 0x03000001;
//    public final static long SSL3_CK_RSA_NULL_SHA = 0x03000002;
//    public final static long SSL3_CK_RSA_RC4_40_MD5 = 0x03000003;
//    public final static long SSL3_CK_RSA_RC4_128_MD5 = 0x03000004;
//    public final static long SSL3_CK_RSA_RC4_128_SHA = 0x03000005;
//    public final static long SSL3_CK_RSA_RC2_40_MD5 = 0x03000006;
//    public final static long SSL3_CK_RSA_IDEA_128_SHA = 0x03000007;
//    public final static long SSL3_CK_RSA_DES_40_CBC_SHA = 0x03000008;
//    public final static long SSL3_CK_RSA_DES_64_CBC_SHA = 0x03000009;
//    public final static long SSL3_CK_RSA_DES_192_CBC3_SHA = 0x0300000A;
//    public final static long SSL3_CK_DH_DSS_DES_40_CBC_SHA = 0x0300000B;
//    public final static long SSL3_CK_DH_DSS_DES_64_CBC_SHA = 0x0300000C;
//    public final static long SSL3_CK_DH_DSS_DES_192_CBC3_SHA = 0x0300000D;
//    public final static long SSL3_CK_DH_RSA_DES_40_CBC_SHA = 0x0300000E;
//    public final static long SSL3_CK_DH_RSA_DES_64_CBC_SHA = 0x0300000F;
//    public final static long SSL3_CK_DH_RSA_DES_192_CBC3_SHA = 0x03000010;
//    public final static long SSL3_CK_EDH_DSS_DES_40_CBC_SHA = 0x03000011;
//    public final static long SSL3_CK_EDH_DSS_DES_64_CBC_SHA = 0x03000012;
//    public final static long SSL3_CK_EDH_DSS_DES_192_CBC3_SHA = 0x03000013;
//    public final static long SSL3_CK_EDH_RSA_DES_40_CBC_SHA = 0x03000014;
//    public final static long SSL3_CK_EDH_RSA_DES_64_CBC_SHA = 0x03000015;
//    public final static long SSL3_CK_EDH_RSA_DES_192_CBC3_SHA = 0x03000016;
//    public final static long SSL3_CK_ADH_RC4_40_MD5 = 0x03000017;
//    public final static long SSL3_CK_ADH_RC4_128_MD5 = 0x03000018;
//    public final static long SSL3_CK_ADH_DES_40_CBC_SHA = 0x03000019;
//    public final static long SSL3_CK_ADH_DES_64_CBC_SHA = 0x0300001A;
//    public final static long SSL3_CK_ADH_DES_192_CBC_SHA = 0x0300001B;
    public final static long SSL3_CK_FZA_DMS_NULL_SHA = 0x0300001C;
    public final static long SSL3_CK_FZA_DMS_FZA_SHA = 0x0300001D;
    public final static long SSL3_CK_KRB5_DES_64_CBC_SHA = 0x0300001E;
    public final static long SSL3_CK_KRB5_DES_192_CBC3_SHA = 0x0300001F;
    public final static long SSL3_CK_KRB5_RC4_128_SHA = 0x03000020;
    public final static long SSL3_CK_KRB5_IDEA_128_CBC_SHA = 0x03000021;
    public final static long SSL3_CK_KRB5_DES_64_CBC_MD5 = 0x03000022;
    public final static long SSL3_CK_KRB5_DES_192_CBC3_MD5 = 0x03000023;
    public final static long SSL3_CK_KRB5_RC4_128_MD5 = 0x03000024;
    public final static long SSL3_CK_KRB5_IDEA_128_CBC_MD5 = 0x03000025;
    public final static long SSL3_CK_KRB5_DES_40_CBC_SHA = 0x03000026;
    public final static long SSL3_CK_KRB5_RC2_40_CBC_SHA = 0x03000027;
    public final static long SSL3_CK_KRB5_RC4_40_SHA = 0x03000028;
    public final static long SSL3_CK_KRB5_DES_40_CBC_MD5 = 0x03000029;
    public final static long SSL3_CK_KRB5_RC2_40_CBC_MD5 = 0x0300002A;
    public final static long SSL3_CK_KRB5_RC4_40_MD5 = 0x0300002B;

    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5 = 0x03000060;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = 0x03000061;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA = 0x03000062;
    public final static long TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 0x03000063;
    public final static long TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA = 0x03000064;
    public final static long TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = 0x03000065;
    public final static long TLS1_CK_DHE_DSS_WITH_RC4_128_SHA = 0x03000066;
//    public final static long TLS1_CK_RSA_WITH_AES_128_SHA = 0x0300002F;
//    public final static long TLS1_CK_DH_DSS_WITH_AES_128_SHA = 0x03000030;
//    public final static long TLS1_CK_DH_RSA_WITH_AES_128_SHA = 0x03000031;
//    public final static long TLS1_CK_DHE_DSS_WITH_AES_128_SHA = 0x03000032;
//    public final static long TLS1_CK_DHE_RSA_WITH_AES_128_SHA = 0x03000033;
//    public final static long TLS1_CK_ADH_WITH_AES_128_SHA = 0x03000034;
//    public final static long TLS1_CK_RSA_WITH_AES_256_SHA = 0x03000035;
//    public final static long TLS1_CK_DH_DSS_WITH_AES_256_SHA = 0x03000036;
//    public final static long TLS1_CK_DH_RSA_WITH_AES_256_SHA = 0x03000037;
//    public final static long TLS1_CK_DHE_DSS_WITH_AES_256_SHA = 0x03000038;
//    public final static long TLS1_CK_DHE_RSA_WITH_AES_256_SHA = 0x03000039;
//    public final static long TLS1_CK_ADH_WITH_AES_256_SHA = 0x0300003A;
//    public final static long TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA = 0x0300C001;
//    public final static long TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA = 0x0300C002;
//    public final static long TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C003;
//    public final static long TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C004;
//    public final static long TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C005;
//    public final static long TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA = 0x0300C006;
//    public final static long TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA = 0x0300C007;
//    public final static long TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = 0x0300C008;
    public final static long TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0x0300C009;
    public final static long TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0x0300C00A;
//    public final static long TLS1_CK_ECDH_RSA_WITH_NULL_SHA = 0x0300C00B;
//    public final static long TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA = 0x0300C00C;
//    public final static long TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA = 0x0300C00D;
    public final static long TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0x0300C00E;
    public final static long TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0x0300C00F;
//    public final static long TLS1_CK_ECDHE_RSA_WITH_NULL_SHA = 0x0300C010;
//    public final static long TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA = 0x0300C011;
//    public final static long TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA = 0x0300C012;
    public final static long TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0x0300C013;
    public final static long TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0x0300C014;
//    public final static long TLS1_CK_ECDH_anon_WITH_NULL_SHA = 0x0300C015;
    public final static long TLS_ECDH_anon_WITH_RC4_128_SHA = 0x0300C016;
    public final static long TLS_ECDH_anon_WITH_DES_192_CBC3_SHA = 0x0300C017;
    public final static long TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0x0300C018;
    public final static long TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0x0300C019;
    
    public final static long  TLS1_CK_PSK_WITH_RC4_128_SHA                    = 0x0300008A;
    public final static long  TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA               = 0x0300008B;
    public final static long  TLS1_CK_PSK_WITH_AES_128_CBC_SHA                = 0x0300008C;
    public final static long  TLS1_CK_PSK_WITH_AES_256_CBC_SHA                = 0x0300008D;
    public final static long  TLS1_CK_DHE_PSK_WITH_RC4_128_SHA                = 0x0300008E;
    public final static long  TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA           = 0x0300008F;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA            = 0x03000090;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA            = 0x03000091;
    public final static long  TLS1_CK_RSA_PSK_WITH_RC4_128_SHA                = 0x03000092;
    public final static long  TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA           = 0x03000093;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA            = 0x03000094;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA            = 0x03000095;

    /* PSK ciphersuites from 5487 */
    public final static long  TLS1_CK_PSK_WITH_AES_128_GCM_SHA256             = 0x030000A8;
    public final static long  TLS1_CK_PSK_WITH_AES_256_GCM_SHA384             = 0x030000A9;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256         = 0x030000AA;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384         = 0x030000AB;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256         = 0x030000AC;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384         = 0x030000AD;
    public final static long  TLS1_CK_PSK_WITH_AES_128_CBC_SHA256             = 0x030000AE;
    public final static long  TLS1_CK_PSK_WITH_AES_256_CBC_SHA384             = 0x030000AF;
    public final static long  TLS1_CK_PSK_WITH_NULL_SHA256                    = 0x030000B0;
    public final static long  TLS1_CK_PSK_WITH_NULL_SHA384                    = 0x030000B1;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256         = 0x030000B2;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384         = 0x030000B3;
    public final static long  TLS1_CK_DHE_PSK_WITH_NULL_SHA256                = 0x030000B4;
    public final static long  TLS1_CK_DHE_PSK_WITH_NULL_SHA384                = 0x030000B5;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256         = 0x030000B6;
    public final static long  TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384         = 0x030000B7;
    public final static long  TLS1_CK_RSA_PSK_WITH_NULL_SHA256                = 0x030000B8;
    public final static long  TLS1_CK_RSA_PSK_WITH_NULL_SHA384                = 0x030000B9;

    /* NULL PSK ciphersuites from RFC4785 */
    public final static long  TLS1_CK_PSK_WITH_NULL_SHA                       = 0x0300002C;
    public final static long  TLS1_CK_DHE_PSK_WITH_NULL_SHA                   = 0x0300002D;
    public final static long  TLS1_CK_RSA_PSK_WITH_NULL_SHA                   = 0x0300002E;

    /* AES ciphersuites from RFC3268 */
    public final static long  TLS1_CK_RSA_WITH_AES_128_SHA                    = 0x0300002F;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_128_SHA                 = 0x03000030;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_128_SHA                 = 0x03000031;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_128_SHA                = 0x03000032;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_128_SHA                = 0x03000033;
    public final static long  TLS1_CK_ADH_WITH_AES_128_SHA                    = 0x03000034;
    public final static long  TLS1_CK_RSA_WITH_AES_256_SHA                    = 0x03000035;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_256_SHA                 = 0x03000036;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_256_SHA                 = 0x03000037;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_256_SHA                = 0x03000038;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_256_SHA                = 0x03000039;
    public final static long  TLS1_CK_ADH_WITH_AES_256_SHA                    = 0x0300003A;

    /* TLS v1.2 ciphersuites */
    public final static long  TLS1_CK_RSA_WITH_NULL_SHA256                    = 0x0300003B;
    public final static long  TLS1_CK_RSA_WITH_AES_128_SHA256                 = 0x0300003C;
    public final static long  TLS1_CK_RSA_WITH_AES_256_SHA256                 = 0x0300003D;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_128_SHA256              = 0x0300003E;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_128_SHA256              = 0x0300003F;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_128_SHA256             = 0x03000040;
;
    /* Camellia ciphersuites from RFC4132 */;
    public final static long  TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA           = 0x03000041;
    public final static long  TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA        = 0x03000042;
    public final static long  TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA        = 0x03000043;
    public final static long  TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA       = 0x03000044;
    public final static long  TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA       = 0x03000045;
    public final static long  TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA           = 0x03000046;

    /* TLS v1.2 ciphersuites */
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_128_SHA256             = 0x03000067;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_256_SHA256              = 0x03000068;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_256_SHA256              = 0x03000069;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_256_SHA256             = 0x0300006A;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_256_SHA256             = 0x0300006B;
    public final static long  TLS1_CK_ADH_WITH_AES_128_SHA256                 = 0x0300006C;
    public final static long  TLS1_CK_ADH_WITH_AES_256_SHA256                 = 0x0300006D;

    /* Camellia ciphersuites from RFC4132 */
    public final static long  TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA           = 0x03000084;
    public final static long  TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA        = 0x03000085;
    public final static long  TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA        = 0x03000086;
    public final static long  TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA       = 0x03000087;
    public final static long  TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA       = 0x03000088;
    public final static long  TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA           = 0x03000089;

    /* SEED ciphersuites from RFC4162 */;
    public final static long  TLS1_CK_RSA_WITH_SEED_SHA                       = 0x03000096;
    public final static long  TLS1_CK_DH_DSS_WITH_SEED_SHA                    = 0x03000097;
    public final static long  TLS1_CK_DH_RSA_WITH_SEED_SHA                    = 0x03000098;
    public final static long  TLS1_CK_DHE_DSS_WITH_SEED_SHA                   = 0x03000099;
    public final static long  TLS1_CK_DHE_RSA_WITH_SEED_SHA                   = 0x0300009A;
    public final static long  TLS1_CK_ADH_WITH_SEED_SHA                       = 0x0300009B;

    /* TLS v1.2 GCM ciphersuites from RFC5288 */
    public final static long  TLS1_CK_RSA_WITH_AES_128_GCM_SHA256             = 0x0300009C;
    public final static long  TLS1_CK_RSA_WITH_AES_256_GCM_SHA384             = 0x0300009D;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256         = 0x0300009E;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384         = 0x0300009F;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256          = 0x030000A0;
    public final static long  TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384          = 0x030000A1;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256         = 0x030000A2;
    public final static long  TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384         = 0x030000A3;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256          = 0x030000A4;
    public final static long  TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384          = 0x030000A5;
    public final static long  TLS1_CK_ADH_WITH_AES_128_GCM_SHA256             = 0x030000A6;
    public final static long  TLS1_CK_ADH_WITH_AES_256_GCM_SHA384             = 0x030000A7;

    /* CCM ciphersuites from RFC6655 */;;
    public final static long  TLS1_CK_RSA_WITH_AES_128_CCM                    = 0x0300C09C;
    public final static long  TLS1_CK_RSA_WITH_AES_256_CCM                    = 0x0300C09D;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_128_CCM                = 0x0300C09E;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_256_CCM                = 0x0300C09F;
    public final static long  TLS1_CK_RSA_WITH_AES_128_CCM_8                  = 0x0300C0A0;
    public final static long  TLS1_CK_RSA_WITH_AES_256_CCM_8                  = 0x0300C0A1;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8              = 0x0300C0A2;
    public final static long  TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8              = 0x0300C0A3;
    public final static long  TLS1_CK_PSK_WITH_AES_128_CCM                    = 0x0300C0A4;
    public final static long  TLS1_CK_PSK_WITH_AES_256_CCM                    = 0x0300C0A5;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_128_CCM                = 0x0300C0A6;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_256_CCM                = 0x0300C0A7;
    public final static long  TLS1_CK_PSK_WITH_AES_128_CCM_8                  = 0x0300C0A8;
    public final static long  TLS1_CK_PSK_WITH_AES_256_CCM_8                  = 0x0300C0A9;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8              = 0x0300C0AA;
    public final static long  TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8              = 0x0300C0AB;

    /* CCM ciphersuites from RFC7251 */
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM            = 0x0300C0AC;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM            = 0x0300C0AD;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8          = 0x0300C0AE;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8          = 0x0300C0AF;

    /* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
    public final static long  TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256                = 0x030000BA;
    public final static long  TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256             = 0x030000BB;
    public final static long  TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256             = 0x030000BC;
    public final static long  TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256            = 0x030000BD;
    public final static long  TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256            = 0x030000BE;
    public final static long  TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256                = 0x030000BF;

    public final static long  TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256                = 0x030000C0;
    public final static long  TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256             = 0x030000C1;
    public final static long  TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256             = 0x030000C2;
    public final static long  TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256            = 0x030000C3;
    public final static long  TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256            = 0x030000C4;
    public final static long  TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256                = 0x030000C5;

    /* ECC ciphersuites from RFC4492 */
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA                = 0x0300C001;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA             = 0x0300C002;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA        = 0x0300C003;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA         = 0x0300C004;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA         = 0x0300C005;
;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA               = 0x0300C006;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA            = 0x0300C007;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA       = 0x0300C008;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        = 0x0300C009;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        = 0x0300C00A;

    public final static long  TLS1_CK_ECDH_RSA_WITH_NULL_SHA                  = 0x0300C00B;
    public final static long  TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA               = 0x0300C00C;
    public final static long  TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA          = 0x0300C00D;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA           = 0x0300C00E;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA           = 0x0300C00F;

    public final static long  TLS1_CK_ECDHE_RSA_WITH_NULL_SHA                 = 0x0300C010;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA              = 0x0300C011;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA         = 0x0300C012;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA          = 0x0300C013;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA          = 0x0300C014;

    public final static long  TLS1_CK_ECDH_anon_WITH_NULL_SHA                 = 0x0300C015;
    public final static long  TLS1_CK_ECDH_anon_WITH_RC4_128_SHA              = 0x0300C016;
    public final static long  TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA         = 0x0300C017;
    public final static long  TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA          = 0x0300C018;
    public final static long  TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA          = 0x0300C019;

    /* SRP ciphersuites from RFC 5054 */
    public final static long  TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA           = 0x0300C01A;
    public final static long  TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA       = 0x0300C01B;
    public final static long  TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA       = 0x0300C01C;
    public final static long  TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA            = 0x0300C01D;
    public final static long  TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA        = 0x0300C01E;
    public final static long  TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA        = 0x0300C01F;
    public final static long  TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA            = 0x0300C020;
    public final static long  TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA        = 0x0300C021;
    public final static long  TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA        = 0x0300C022;

    /* ECDH HMAC based ciphersuites from RFC5289 */
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256         = 0x0300C023;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384         = 0x0300C024;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256          = 0x0300C025;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384          = 0x0300C026;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256           = 0x0300C027;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384           = 0x0300C028;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256            = 0x0300C029;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384            = 0x0300C02A;

    /* ECDH GCM based ciphersuites from RFC5289 */
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     = 0x0300C02B;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     = 0x0300C02C;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256      = 0x0300C02D;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384      = 0x0300C02E;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256       = 0x0300C02F;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384       = 0x0300C030;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256        = 0x0300C031;
    public final static long  TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384        = 0x0300C032;

    /* ECDHE PSK ciphersuites from RFC5489 */
    public final static long  TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA              = 0x0300C033;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA         = 0x0300C034;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA          = 0x0300C035;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA          = 0x0300C036;

    public final static long  TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256       = 0x0300C037;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384       = 0x0300C038;

    /* NULL PSK ciphersuites from RFC4785 */
    public final static long  TLS1_CK_ECDHE_PSK_WITH_NULL_SHA                 = 0x0300C039;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256              = 0x0300C03A;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384              = 0x0300C03B;

    /* Camellia-CBC ciphersuites from RFC6367 */
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x0300C072;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0x0300C073;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = 0x0300C074;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = 0x0300C075;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   = 0x0300C076;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   = 0x0300C077;
    public final static long  TLS1_CK_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    = 0x0300C078;
    public final static long  TLS1_CK_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    = 0x0300C079;

    public final static long  TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256         = 0x0300C094;
    public final static long  TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384         = 0x0300C095;
    public final static long  TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256     = 0x0300C096;
    public final static long  TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384     = 0x0300C097;
    public final static long  TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256     = 0x0300C098;
    public final static long  TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384     = 0x0300C099;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   = 0x0300C09A;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   = 0x0300C09B;

    /* draft-ietf-tls-chacha20-poly1305-03 */
    public final static long  TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305         = 0x0300CCA8;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305       = 0x0300CCA9;
    public final static long  TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305           = 0x0300CCAA;
    public final static long  TLS1_CK_PSK_WITH_CHACHA20_POLY1305               = 0x0300CCAB;
    public final static long  TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305         = 0x0300CCAC;
    public final static long  TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305           = 0x0300CCAD;
    public final static long  TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305           = 0x0300CCAE;

    /* TLS v1.3 ciphersuites */
    public final static long  TLS1_3_CK_AES_128_GCM_SHA256                     = 0x03001301;
    public final static long  TLS1_3_CK_AES_256_GCM_SHA384                     = 0x03001302;
    public final static long  TLS1_3_CK_CHACHA20_POLY1305_SHA256               = 0x03001303;
    public final static long  TLS1_3_CK_AES_128_CCM_SHA256                     = 0x03001304;
    public final static long  TLS1_3_CK_AES_128_CCM_8_SHA256                   = 0x03001305;

    /* Aria ciphersuites from RFC6209 */
    public final static long  TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256             = 0x0300C050;
    public final static long  TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384             = 0x0300C051;
    public final static long  TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256         = 0x0300C052;
    public final static long  TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384         = 0x0300C053;
    public final static long  TLS1_CK_DH_RSA_WITH_ARIA_128_GCM_SHA256          = 0x0300C054;
    public final static long  TLS1_CK_DH_RSA_WITH_ARIA_256_GCM_SHA384          = 0x0300C055;
    public final static long  TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256         = 0x0300C056;
    public final static long  TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384         = 0x0300C057;
    public final static long  TLS1_CK_DH_DSS_WITH_ARIA_128_GCM_SHA256          = 0x0300C058;
    public final static long  TLS1_CK_DH_DSS_WITH_ARIA_256_GCM_SHA384          = 0x0300C059;
    public final static long  TLS1_CK_DH_anon_WITH_ARIA_128_GCM_SHA256         = 0x0300C05A;
    public final static long  TLS1_CK_DH_anon_WITH_ARIA_256_GCM_SHA384         = 0x0300C05B;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256     = 0x0300C05C;
    public final static long  TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384     = 0x0300C05D;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256      = 0x0300C05E;
    public final static long  TLS1_CK_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384      = 0x0300C05F;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256       = 0x0300C060;
    public final static long  TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384       = 0x0300C061;
    public final static long  TLS1_CK_ECDH_RSA_WITH_ARIA_128_GCM_SHA256        = 0x0300C062;
    public final static long  TLS1_CK_ECDH_RSA_WITH_ARIA_256_GCM_SHA384        = 0x0300C063;
    public final static long  TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256             = 0x0300C06A;
    public final static long  TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384             = 0x0300C06B;
    public final static long  TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256         = 0x0300C06C;
    public final static long  TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384         = 0x0300C06D;
    public final static long  TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256         = 0x0300C06E;
    public final static long  TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384         = 0x0300C06F;


    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5 = "EXP1024-RC4-MD5";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 = "EXP1024-RC2-CBC-MD5";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DES-CBC-SHA";
    public final static String TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = "EXP1024-DHE-DSS-DES-CBC-SHA";
    public final static String TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-RC4-SHA";
    public final static String TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA = "EXP1024-DHE-DSS-RC4-SHA";
//    public final static String TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA = "DHE-DSS-RC4-SHA";
//    public final static String TLS1_TXT_RSA_WITH_AES_128_SHA = "AES128-SHA";
//    public final static String TLS1_TXT_DH_DSS_WITH_AES_128_SHA = "DH-DSS-AES128-SHA";
//    public final static String TLS1_TXT_DH_RSA_WITH_AES_128_SHA = "DH-RSA-AES128-SHA";
//    public final static String TLS1_TXT_DHE_DSS_WITH_AES_128_SHA = "DHE-DSS-AES128-SHA";
//    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_SHA = "DHE-RSA-AES128-SHA";
//    public final static String TLS1_TXT_ADH_WITH_AES_128_SHA = "ADH-AES128-SHA";
//    public final static String TLS1_TXT_RSA_WITH_AES_256_SHA = "AES256-SHA";
//    public final static String TLS1_TXT_DH_DSS_WITH_AES_256_SHA = "DH-DSS-AES256-SHA";
//    public final static String TLS1_TXT_DH_RSA_WITH_AES_256_SHA = "DH-RSA-AES256-SHA";
//    public final static String TLS1_TXT_DHE_DSS_WITH_AES_256_SHA = "DHE-DSS-AES256-SHA";
//    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_SHA = "DHE-RSA-AES256-SHA";
//    public final static String TLS1_TXT_ADH_WITH_AES_256_SHA = "ADH-AES256-SHA";
//    public final static String TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA = "ECDH-ECDSA-NULL-SHA";
//    public final static String TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA = "ECDH-ECDSA-RC4-SHA";
//    public final static String TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA = "ECDH-ECDSA-DES-CBC3-SHA";
//    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA = "ECDHE-ECDSA-NULL-SHA";
//    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA = "ECDHE-ECDSA-RC4-SHA";
//    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA = "ECDHE-ECDSA-DES-CBC3-SHA";
//    public final static String TLS1_TXT_ECDH_RSA_WITH_NULL_SHA = "ECDH-RSA-NULL-SHA";
//    public final static String TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA = "ECDH-RSA-RC4-SHA";
//    public final static String TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA = "ECDH-RSA-DES-CBC3-SHA";
//    public final static String TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA = "ECDHE-RSA-NULL-SHA";
//    public final static String TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA = "ECDHE-RSA-RC4-SHA";
//    public final static String TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA = "ECDHE-RSA-DES-CBC3-SHA";
//    public final static String TLS1_TXT_ECDH_anon_WITH_NULL_SHA = "AECDH-NULL-SHA";
//    
//    public final static String TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA               = "DHE-DSS-RC4-SHA";

    public final static String TLS1_TXT_PSK_WITH_NULL_SHA                     = "PSK-NULL-SHA";
    public final static String TLS1_TXT_DHE_PSK_WITH_NULL_SHA                 = "DHE-PSK-NULL-SHA";
    public final static String TLS1_TXT_RSA_PSK_WITH_NULL_SHA                 = "RSA-PSK-NULL-SHA";

    /* AES ciphersuites from RFC3268 */
    public final static String TLS1_TXT_RSA_WITH_AES_128_SHA                  = "AES128-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_128_SHA               = "DH-DSS-AES128-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_128_SHA               = "DH-RSA-AES128-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_128_SHA              = "DHE-DSS-AES128-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_SHA              = "DHE-RSA-AES128-SHA";
    public final static String TLS1_TXT_ADH_WITH_AES_128_SHA                  = "ADH-AES128-SHA";

    public final static String TLS1_TXT_RSA_WITH_AES_256_SHA                  = "AES256-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_256_SHA               = "DH-DSS-AES256-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_256_SHA               = "DH-RSA-AES256-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_256_SHA              = "DHE-DSS-AES256-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_SHA              = "DHE-RSA-AES256-SHA";
    public final static String TLS1_TXT_ADH_WITH_AES_256_SHA                  = "ADH-AES256-SHA";

    /* ECC ciphersuites from RFC4492 */
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA              = "ECDH-ECDSA-NULL-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA           = "ECDH-ECDSA-RC4-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA      = "ECDH-ECDSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA       = "ECDH-ECDSA-AES128-SHA";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA       = "ECDH-ECDSA-AES256-SHA";

    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA             = "ECDHE-ECDSA-NULL-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA          = "ECDHE-ECDSA-RC4-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA     = "ECDHE-ECDSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA      = "ECDHE-ECDSA-AES128-SHA";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA      = "ECDHE-ECDSA-AES256-SHA";

    public final static String TLS1_TXT_ECDH_RSA_WITH_NULL_SHA                = "ECDH-RSA-NULL-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA             = "ECDH-RSA-RC4-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA        = "ECDH-RSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA         = "ECDH-RSA-AES128-SHA";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA         = "ECDH-RSA-AES256-SHA";

    public final static String TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA               = "ECDHE-RSA-NULL-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA            = "ECDHE-RSA-RC4-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA       = "ECDHE-RSA-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA        = "ECDHE-RSA-AES128-SHA";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA        = "ECDHE-RSA-AES256-SHA";

    public final static String TLS1_TXT_ECDH_anon_WITH_NULL_SHA               = "AECDH-NULL-SHA";
    public final static String TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA            = "AECDH-RC4-SHA";
    public final static String TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA       = "AECDH-DES-CBC3-SHA";
    public final static String TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA        = "AECDH-AES128-SHA";
    public final static String TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA        = "AECDH-AES256-SHA";

    
    /* PSK ciphersuites from RFC 4279 */
    public final static String TLS1_TXT_PSK_WITH_RC4_128_SHA                  = "PSK-RC4-SHA";
    public final static String TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA             = "PSK-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_PSK_WITH_AES_128_CBC_SHA              = "PSK-AES128-CBC-SHA";
    public final static String TLS1_TXT_PSK_WITH_AES_256_CBC_SHA              = "PSK-AES256-CBC-SHA";

    public final static String TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA              = "DHE-PSK-RC4-SHA";
    public final static String TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA         = "DHE-PSK-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA          = "DHE-PSK-AES128-CBC-SHA";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA          = "DHE-PSK-AES256-CBC-SHA";
    public final static String TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA              = "RSA-PSK-RC4-SHA";
    public final static String TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA         = "RSA-PSK-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA          = "RSA-PSK-AES128-CBC-SHA";
    public final static String TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA          = "RSA-PSK-AES256-CBC-SHA";

    /* PSK ciphersuites from RFC 5487 */
    public final static String TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256           = "PSK-AES128-GCM-SHA256";
    public final static String TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384           = "PSK-AES256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256       = "DHE-PSK-AES128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384       = "DHE-PSK-AES256-GCM-SHA384";
    public final static String TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256       = "RSA-PSK-AES128-GCM-SHA256";
    public final static String TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384       = "RSA-PSK-AES256-GCM-SHA384";

    public final static String TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256           = "PSK-AES128-CBC-SHA256";
    public final static String TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384           = "PSK-AES256-CBC-SHA384";
    public final static String TLS1_TXT_PSK_WITH_NULL_SHA256                  = "PSK-NULL-SHA256";
    public final static String TLS1_TXT_PSK_WITH_NULL_SHA384                  = "PSK-NULL-SHA384";

    public final static String TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256       = "DHE-PSK-AES128-CBC-SHA256";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384       = "DHE-PSK-AES256-CBC-SHA384";
    public final static String TLS1_TXT_DHE_PSK_WITH_NULL_SHA256              = "DHE-PSK-NULL-SHA256";
    public final static String TLS1_TXT_DHE_PSK_WITH_NULL_SHA384              = "DHE-PSK-NULL-SHA384";

    public final static String TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256       = "RSA-PSK-AES128-CBC-SHA256";
    public final static String TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384       = "RSA-PSK-AES256-CBC-SHA384";
    public final static String TLS1_TXT_RSA_PSK_WITH_NULL_SHA256              = "RSA-PSK-NULL-SHA256";
    public final static String TLS1_TXT_RSA_PSK_WITH_NULL_SHA384              = "RSA-PSK-NULL-SHA384";

    /* SRP ciphersuite from RFC 5054 */
    public final static String TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA         = "SRP-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA     = "SRP-RSA-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA     = "SRP-DSS-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA          = "SRP-AES-128-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA      = "SRP-RSA-AES-128-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA      = "SRP-DSS-AES-128-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA          = "SRP-AES-256-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA      = "SRP-RSA-AES-256-CBC-SHA";
    public final static String TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA      = "SRP-DSS-AES-256-CBC-SHA";

    /* Camellia ciphersuites from RFC4132 */
    public final static String TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA         = "CAMELLIA128-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA      = "DH-DSS-CAMELLIA128-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA      = "DH-RSA-CAMELLIA128-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA     = "DHE-DSS-CAMELLIA128-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA     = "DHE-RSA-CAMELLIA128-SHA";
    public final static String TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA         = "ADH-CAMELLIA128-SHA";

    public final static String TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA         = "CAMELLIA256-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA      = "DH-DSS-CAMELLIA256-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA      = "DH-RSA-CAMELLIA256-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA     = "DHE-DSS-CAMELLIA256-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA     = "DHE-RSA-CAMELLIA256-SHA";
    public final static String TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA         = "ADH-CAMELLIA256-SHA";

    /* TLS 1.2 Camellia SHA-256 ciphersuites from RFC5932 */
    public final static String TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256              = "CAMELLIA128-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256           = "DH-DSS-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256           = "DH-RSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256          = "DHE-DSS-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256          = "DHE-RSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256              = "ADH-CAMELLIA128-SHA256";

    public final static String TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256              = "CAMELLIA256-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256           = "DH-DSS-CAMELLIA256-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256           = "DH-RSA-CAMELLIA256-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256          = "DHE-DSS-CAMELLIA256-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256          = "DHE-RSA-CAMELLIA256-SHA256";
    public final static String TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256              = "ADH-CAMELLIA256-SHA256";

    public final static String TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256              = "PSK-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384              = "PSK-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256          = "DHE-PSK-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384          = "DHE-PSK-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256          = "RSA-PSK-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384          = "RSA-PSK-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256        = "ECDHE-PSK-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384        = "ECDHE-PSK-CAMELLIA256-SHA384";

    /* SEED ciphersuites from RFC4162 */
    public final static String TLS1_TXT_RSA_WITH_SEED_SHA                     = "SEED-SHA";
    public final static String TLS1_TXT_DH_DSS_WITH_SEED_SHA                  = "DH-DSS-SEED-SHA";
    public final static String TLS1_TXT_DH_RSA_WITH_SEED_SHA                  = "DH-RSA-SEED-SHA";
    public final static String TLS1_TXT_DHE_DSS_WITH_SEED_SHA                 = "DHE-DSS-SEED-SHA";
    public final static String TLS1_TXT_DHE_RSA_WITH_SEED_SHA                 = "DHE-RSA-SEED-SHA";
    public final static String TLS1_TXT_ADH_WITH_SEED_SHA                     = "ADH-SEED-SHA";

    /* TLS v1.2 ciphersuites */
    public final static String TLS1_TXT_RSA_WITH_NULL_SHA256                  = "NULL-SHA256";
    public final static String TLS1_TXT_RSA_WITH_AES_128_SHA256               = "AES128-SHA256";
    public final static String TLS1_TXT_RSA_WITH_AES_256_SHA256               = "AES256-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_128_SHA256            = "DH-DSS-AES128-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_128_SHA256            = "DH-RSA-AES128-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256           = "DHE-DSS-AES128-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256           = "DHE-RSA-AES128-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_256_SHA256            = "DH-DSS-AES256-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_256_SHA256            = "DH-RSA-AES256-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256           = "DHE-DSS-AES256-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256           = "DHE-RSA-AES256-SHA256";
    public final static String TLS1_TXT_ADH_WITH_AES_128_SHA256               = "ADH-AES128-SHA256";
    public final static String TLS1_TXT_ADH_WITH_AES_256_SHA256               = "ADH-AES256-SHA256";

    /* TLS v1.2 GCM ciphersuites from RFC5288 */
    public final static String TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256           = "AES128-GCM-SHA256";
    public final static String TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384           = "AES256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256       = "DHE-RSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384       = "DHE-RSA-AES256-GCM-SHA384";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256        = "DH-RSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384        = "DH-RSA-AES256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256       = "DHE-DSS-AES128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384       = "DHE-DSS-AES256-GCM-SHA384";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256        = "DH-DSS-AES128-GCM-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384        = "DH-DSS-AES256-GCM-SHA384";
    public final static String TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256           = "ADH-AES128-GCM-SHA256";
    public final static String TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384           = "ADH-AES256-GCM-SHA384";

    /* CCM ciphersuites from RFC6655 */
    public final static String TLS1_TXT_RSA_WITH_AES_128_CCM                  = "AES128-CCM";
    public final static String TLS1_TXT_RSA_WITH_AES_256_CCM                  = "AES256-CCM";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_CCM              = "DHE-RSA-AES128-CCM";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_CCM              = "DHE-RSA-AES256-CCM";

    public final static String TLS1_TXT_RSA_WITH_AES_128_CCM_8                = "AES128-CCM8";
    public final static String TLS1_TXT_RSA_WITH_AES_256_CCM_8                = "AES256-CCM8";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8            = "DHE-RSA-AES128-CCM8";
    public final static String TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8            = "DHE-RSA-AES256-CCM8";

    public final static String TLS1_TXT_PSK_WITH_AES_128_CCM                  = "PSK-AES128-CCM";
    public final static String TLS1_TXT_PSK_WITH_AES_256_CCM                  = "PSK-AES256-CCM";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_128_CCM              = "DHE-PSK-AES128-CCM";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_256_CCM              = "DHE-PSK-AES256-CCM";

    public final static String TLS1_TXT_PSK_WITH_AES_128_CCM_8                = "PSK-AES128-CCM8";
    public final static String TLS1_TXT_PSK_WITH_AES_256_CCM_8                = "PSK-AES256-CCM8";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8            = "DHE-PSK-AES128-CCM8";
    public final static String TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8            = "DHE-PSK-AES256-CCM8";

    /* CCM ciphersuites from RFC7251 */
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM      = "ECDHE-ECDSA-AES128-CCM";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM      = "ECDHE-ECDSA-AES256-CCM";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8    = "ECDHE-ECDSA-AES128-CCM8";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8    = "ECDHE-ECDSA-AES256-CCM8";

    /* ECDH HMAC based ciphersuites from RFC5289 */
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256   = "ECDHE-ECDSA-AES128-SHA256";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384   = "ECDHE-ECDSA-AES256-SHA384";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256    = "ECDH-ECDSA-AES128-SHA256";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384    = "ECDH-ECDSA-AES256-SHA384";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256     = "ECDHE-RSA-AES128-SHA256";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384     = "ECDHE-RSA-AES256-SHA384";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256      = "ECDH-RSA-AES128-SHA256";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384      = "ECDH-RSA-AES256-SHA384";

    /* ECDH GCM based ciphersuites from RFC5289 */
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   = "ECDHE-ECDSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   = "ECDHE-ECDSA-AES256-GCM-SHA384";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256    = "ECDH-ECDSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384    = "ECDH-ECDSA-AES256-GCM-SHA384";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256     = "ECDHE-RSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384     = "ECDHE-RSA-AES256-GCM-SHA384";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256      = "ECDH-RSA-AES128-GCM-SHA256";
    public final static String TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384      = "ECDH-RSA-AES256-GCM-SHA384";

    /* TLS v1.2 PSK GCM ciphersuites from RFC5487 */
//    public final static String TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256           = "PSK-AES128-GCM-SHA256";
//    public final static String TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384           = "PSK-AES256-GCM-SHA384";

    /* ECDHE PSK ciphersuites from RFC 5489 */
    public final static String TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA              = "ECDHE-PSK-RC4-SHA";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA         = "ECDHE-PSK-3DES-EDE-CBC-SHA";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA          = "ECDHE-PSK-AES128-CBC-SHA";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA          = "ECDHE-PSK-AES256-CBC-SHA";

    public final static String TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256       = "ECDHE-PSK-AES128-CBC-SHA256";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384       = "ECDHE-PSK-AES256-CBC-SHA384";

    public final static String TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA                 = "ECDHE-PSK-NULL-SHA";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256              = "ECDHE-PSK-NULL-SHA256";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384              = "ECDHE-PSK-NULL-SHA384";

    /* Camellia-CBC ciphersuites from RFC6367 */
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256= "ECDHE-ECDSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384= "ECDHE-ECDSA-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = "ECDH-ECDSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = "ECDH-ECDSA-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256  = "ECDHE-RSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384  = "ECDHE-RSA-CAMELLIA256-SHA384";
    public final static String TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256   = "ECDH-RSA-CAMELLIA128-SHA256";
    public final static String TLS1_TXT_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384   = "ECDH-RSA-CAMELLIA256-SHA384";

    /* draft-ietf-tls-chacha20-poly1305-03 */
    public final static String TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305        = "ECDHE-RSA-CHACHA20-POLY1305";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305      = "ECDHE-ECDSA-CHACHA20-POLY1305";
    public final static String TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305          = "DHE-RSA-CHACHA20-POLY1305";
    public final static String TLS1_TXT_PSK_WITH_CHACHA20_POLY1305              = "PSK-CHACHA20-POLY1305";
    public final static String TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305        = "ECDHE-PSK-CHACHA20-POLY1305";
    public final static String TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305          = "DHE-PSK-CHACHA20-POLY1305";
    public final static String TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305          = "RSA-PSK-CHACHA20-POLY1305";

    /* Aria ciphersuites from RFC6209 */
    public final static String TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256            = "ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384            = "ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256        = "DHE-RSA-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384        = "DHE-RSA-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DH_RSA_WITH_ARIA_128_GCM_SHA256         = "DH-RSA-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DH_RSA_WITH_ARIA_256_GCM_SHA384         = "DH-RSA-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256        = "DHE-DSS-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384        = "DHE-DSS-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DH_DSS_WITH_ARIA_128_GCM_SHA256         = "DH-DSS-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DH_DSS_WITH_ARIA_256_GCM_SHA384         = "DH-DSS-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DH_anon_WITH_ARIA_128_GCM_SHA256        = "ADH-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DH_anon_WITH_ARIA_256_GCM_SHA384        = "ADH-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256    = "ECDHE-ECDSA-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384    = "ECDHE-ECDSA-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256     = "ECDH-ECDSA-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384     = "ECDH-ECDSA-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256      = "ECDHE-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384      = "ECDHE-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_ECDH_RSA_WITH_ARIA_128_GCM_SHA256       = "ECDH-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_ECDH_RSA_WITH_ARIA_256_GCM_SHA384       = "ECDH-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256            = "PSK-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384            = "PSK-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256        = "DHE-PSK-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384        = "DHE-PSK-ARIA256-GCM-SHA384";
    public final static String TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256        = "RSA-PSK-ARIA128-GCM-SHA256";
    public final static String TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384        = "RSA-PSK-ARIA256-GCM-SHA384";

    /* a bundle of RFC standard cipher names, generated from ssl3_ciphers[] */
    public final static String SSL3_RFC_RSA_NULL_MD5                  = "TLS_RSA_WITH_NULL_MD5";
    public final static String SSL3_RFC_RSA_NULL_SHA                  = "TLS_RSA_WITH_NULL_SHA";
    public final static String SSL3_RFC_RSA_DES_192_CBC3_SHA          = "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    public final static String SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA      = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
    public final static String SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA      = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
    public final static String SSL3_RFC_ADH_DES_192_CBC_SHA           = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
    public final static String SSL3_RFC_RSA_IDEA_128_SHA              = "TLS_RSA_WITH_IDEA_CBC_SHA";
    public final static String SSL3_RFC_RSA_RC4_128_MD5               = "TLS_RSA_WITH_RC4_128_MD5";
    public final static String SSL3_RFC_RSA_RC4_128_SHA               = "TLS_RSA_WITH_RC4_128_SHA";
    public final static String SSL3_RFC_ADH_RC4_128_MD5               = "TLS_DH_anon_WITH_RC4_128_MD5";

    public final static String SSL3_TXT_RSA_NULL_MD5                  = "NULL-MD5";
    public final static String SSL3_TXT_RSA_NULL_SHA                  = "NULL-SHA";
    public final static String SSL3_TXT_RSA_RC4_40_MD5                = "EXP-RC4-MD5";
    public final static String SSL3_TXT_RSA_RC4_128_MD5               = "RC4-MD5";
    public final static String SSL3_TXT_RSA_RC4_128_SHA               = "RC4-SHA";
    public final static String SSL3_TXT_RSA_RC2_40_MD5                = "EXP-RC2-CBC-MD5";
    public final static String SSL3_TXT_RSA_IDEA_128_SHA              = "IDEA-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_40_CBC_SHA            = "EXP-DES-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_64_CBC_SHA            = "DES-CBC-SHA";
    public final static String SSL3_TXT_RSA_DES_192_CBC3_SHA          = "DES-CBC3-SHA";

    public final static String SSL3_TXT_DH_DSS_DES_40_CBC_SHA         = "EXP-DH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_DSS_DES_64_CBC_SHA         = "DH-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_DSS_DES_192_CBC3_SHA       = "DH-DSS-DES-CBC3-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_40_CBC_SHA         = "EXP-DH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_64_CBC_SHA         = "DH-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DH_RSA_DES_192_CBC3_SHA       = "DH-RSA-DES-CBC3-SHA";

    public final static String SSL3_TXT_DHE_DSS_DES_40_CBC_SHA        = "EXP-DHE-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DHE_DSS_DES_64_CBC_SHA        = "DHE-DSS-DES-CBC-SHA";
    public final static String SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA      = "DHE-DSS-DES-CBC3-SHA";
    public final static String SSL3_TXT_DHE_RSA_DES_40_CBC_SHA        = "EXP-DHE-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DHE_RSA_DES_64_CBC_SHA        = "DHE-RSA-DES-CBC-SHA";
    public final static String SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA      = "DHE-RSA-DES-CBC3-SHA";
    
    public final static String TLS1_RFC_RSA_WITH_AES_128_SHA                   = "TLS_RSA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_128_SHA               = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_128_SHA               = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_ADH_WITH_AES_128_SHA                   = "TLS_DH_anon_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_RSA_WITH_AES_256_SHA                   = "TLS_RSA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_256_SHA               = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_256_SHA               = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_ADH_WITH_AES_256_SHA                   = "TLS_DH_anon_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_RSA_WITH_NULL_SHA256                   = "TLS_RSA_WITH_NULL_SHA256";
    public final static String TLS1_RFC_RSA_WITH_AES_128_SHA256                = "TLS_RSA_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_RSA_WITH_AES_256_SHA256                = "TLS_RSA_WITH_AES_256_CBC_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256            = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256            = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256            = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256            = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
    public final static String TLS1_RFC_ADH_WITH_AES_128_SHA256                = "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_ADH_WITH_AES_256_SHA256                = "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
    public final static String TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256            = "TLS_RSA_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384            = "TLS_RSA_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256        = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384        = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256        = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384        = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256            = "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384            = "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_RSA_WITH_AES_128_CCM                   = "TLS_RSA_WITH_AES_128_CCM";
    public final static String TLS1_RFC_RSA_WITH_AES_256_CCM                   = "TLS_RSA_WITH_AES_256_CCM";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_128_CCM               = "TLS_DHE_RSA_WITH_AES_128_CCM";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_256_CCM               = "TLS_DHE_RSA_WITH_AES_256_CCM";
    public final static String TLS1_RFC_RSA_WITH_AES_128_CCM_8                 = "TLS_RSA_WITH_AES_128_CCM_8";
    public final static String TLS1_RFC_RSA_WITH_AES_256_CCM_8                 = "TLS_RSA_WITH_AES_256_CCM_8";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8             = "TLS_DHE_RSA_WITH_AES_128_CCM_8";
    public final static String TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8             = "TLS_DHE_RSA_WITH_AES_256_CCM_8";
    public final static String TLS1_RFC_PSK_WITH_AES_128_CCM                   = "TLS_PSK_WITH_AES_128_CCM";
    public final static String TLS1_RFC_PSK_WITH_AES_256_CCM                   = "TLS_PSK_WITH_AES_256_CCM";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_128_CCM               = "TLS_DHE_PSK_WITH_AES_128_CCM";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_256_CCM               = "TLS_DHE_PSK_WITH_AES_256_CCM";
    public final static String TLS1_RFC_PSK_WITH_AES_128_CCM_8                 = "TLS_PSK_WITH_AES_128_CCM_8";
    public final static String TLS1_RFC_PSK_WITH_AES_256_CCM_8                 = "TLS_PSK_WITH_AES_256_CCM_8";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8             = "TLS_PSK_DHE_WITH_AES_128_CCM_8";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8             = "TLS_PSK_DHE_WITH_AES_256_CCM_8";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM           = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM           = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8         = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8         = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
    public final static String TLS1_3_RFC_AES_128_GCM_SHA256                   = "TLS_AES_128_GCM_SHA256";
    public final static String TLS1_3_RFC_AES_256_GCM_SHA384                   = "TLS_AES_256_GCM_SHA384";
    public final static String TLS1_3_RFC_CHACHA20_POLY1305_SHA256             = "TLS_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_3_RFC_AES_128_CCM_SHA256                   = "TLS_AES_128_CCM_SHA256";
    public final static String TLS1_3_RFC_AES_128_CCM_8_SHA256                 = "TLS_AES_128_CCM_8_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA              = "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA      = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA                = "TLS_ECDHE_RSA_WITH_NULL_SHA";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA        = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA         = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA         = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_ECDH_anon_WITH_NULL_SHA                = "TLS_ECDH_anon_WITH_NULL_SHA";
    public final static String TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA        = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA         = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA         = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256        = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384        = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256          = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384          = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256    = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384    = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256      = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384      = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_PSK_WITH_NULL_SHA                      = "TLS_PSK_WITH_NULL_SHA";
    public final static String TLS1_RFC_DHE_PSK_WITH_NULL_SHA                  = "TLS_DHE_PSK_WITH_NULL_SHA";
    public final static String TLS1_RFC_RSA_PSK_WITH_NULL_SHA                  = "TLS_RSA_PSK_WITH_NULL_SHA";
    public final static String TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA              = "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_PSK_WITH_AES_128_CBC_SHA               = "TLS_PSK_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_PSK_WITH_AES_256_CBC_SHA               = "TLS_PSK_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA          = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA           = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA           = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA          = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA           = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA           = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256            = "TLS_PSK_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384            = "TLS_PSK_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256        = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384        = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256        = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384        = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
    public final static String TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256            = "TLS_PSK_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384            = "TLS_PSK_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_PSK_WITH_NULL_SHA256                   = "TLS_PSK_WITH_NULL_SHA256";
    public final static String TLS1_RFC_PSK_WITH_NULL_SHA384                   = "TLS_PSK_WITH_NULL_SHA384";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256        = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384        = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_DHE_PSK_WITH_NULL_SHA256               = "TLS_DHE_PSK_WITH_NULL_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_NULL_SHA384               = "TLS_DHE_PSK_WITH_NULL_SHA384";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256        = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384        = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_RSA_PSK_WITH_NULL_SHA256               = "TLS_RSA_PSK_WITH_NULL_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_NULL_SHA384               = "TLS_RSA_PSK_WITH_NULL_SHA384";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA        = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA         = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA         = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256      = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384      = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA                = "TLS_ECDHE_PSK_WITH_NULL_SHA";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256             = "TLS_ECDHE_PSK_WITH_NULL_SHA256";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384             = "TLS_ECDHE_PSK_WITH_NULL_SHA384";
    public final static String TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA          = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA      = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA      = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA           = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA       = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA       = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA           = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA       = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA       = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305         = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305       = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305     = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_PSK_WITH_CHACHA20_POLY1305             = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305       = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305         = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305         = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256";
    public final static String TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256       = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256   = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256       = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256       = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256   = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256   = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
    public final static String TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256       = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256";
    public final static String TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA          = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA      = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA      = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
    public final static String TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA          = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA";
    public final static String TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA          = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
    public final static String TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA      = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA      = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
    public final static String TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA          = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256       = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384       = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256   = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384   = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
    public final static String TLS1_RFC_RSA_WITH_SEED_SHA                      = "TLS_RSA_WITH_SEED_CBC_SHA";
    public final static String TLS1_RFC_DHE_DSS_WITH_SEED_SHA                  = "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
    public final static String TLS1_RFC_DHE_RSA_WITH_SEED_SHA                  = "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
    public final static String TLS1_RFC_ADH_WITH_SEED_SHA                      = "TLS_DH_anon_WITH_SEED_CBC_SHA";
    public final static String TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA             = "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA             = "TLS_ECDH_anon_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA           = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA             = "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_PSK_WITH_RC4_128_SHA                   = "TLS_PSK_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA               = "TLS_RSA_PSK_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA               = "TLS_DHE_PSK_WITH_RC4_128_SHA";
    public final static String TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256           = "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384           = "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256       = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384       = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DH_RSA_WITH_ARIA_128_GCM_SHA256        = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DH_RSA_WITH_ARIA_256_GCM_SHA384        = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256       = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384       = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DH_DSS_WITH_ARIA_128_GCM_SHA256        = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DH_DSS_WITH_ARIA_256_GCM_SHA384        = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DH_anon_WITH_ARIA_128_GCM_SHA256       = "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DH_anon_WITH_ARIA_256_GCM_SHA384       = "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256   = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384   = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256    = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384    = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256     = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384     = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_ECDH_RSA_WITH_ARIA_128_GCM_SHA256      = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_ECDH_RSA_WITH_ARIA_256_GCM_SHA384      = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256           = "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384           = "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256       = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384       = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384";
    public final static String TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256       = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
    public final static String TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384       = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";

    public final static int DTLS1_VERSION                   = 0xFEFF;
    public final static int DTLS1_2_VERSION                 = 0xFEFD;
    public final static int DTLS_MIN_VERSION                = DTLS1_VERSION;
    public final static int TLS_MAX_VERSION                = DTLS1_2_VERSION;
    public final static int DTLS1_VERSION_MAJOR             = 0xFE;

    public final static int DTLS1_BAD_VER                   = 0x0100;

    /* Special value for method supporting multiple versions */
    public final static int DTLS_ANY_VERSION                = 0x1FFFF;
    /* 
     * OpenSSL 0.9.7:

typedef struct ssl_cipher_st
    {
    int valid;
    const char *name;       // text name 
    unsigned long id;       // id, 4 bytes, first is version 
    unsigned long algorithms;   // what ciphers are used 
    unsigned long algo_strength;    // strength and export flags 
    unsigned long algorithm2;   // Extra flags 
    int strength_bits;      // Number of bits really used 
    int alg_bits;           // Number of bits for algorithm 
    unsigned long mask;     // used for matching 
    unsigned long mask_strength;    // also used for matching 
    } SSL_CIPHER;

     * 
     * OpenSSL 1.1.1
    
struct ssl_cipher_st {
    uint32_t valid;
    const char *name;           // text name 
    const char *stdname;        // RFC name 
    uint32_t id;                // id, 4 bytes, first is version 
    uint32_t algorithm_mkey;    // key exchange algorithm 
    uint32_t algorithm_auth;    // server authentication 
    uint32_t algorithm_enc;     // symmetric encryption 
    uint32_t algorithm_mac;     // symmetric authentication 
    int min_tls;                // minimum SSL/TLS protocol version 
    int max_tls;                // maximum SSL/TLS protocol version 
    int min_dtls;               // minimum DTLS protocol version 
    int max_dtls;               // maximum DTLS protocol version 
    uint32_t algo_strength;     // strength and export flags 
    uint32_t algorithm2;        // Extra flags 
    int32_t strength_bits;      // Number of bits really used 
    uint32_t alg_bits;          // Number of bits for algorithm 
};

     */
    static final class Def implements Comparable<Def>, Cloneable {

        //private final byte valid;
        final String name;
        final String stdname;
        //private final long id;
        long algorithm_mkey;    // key exchange algorithm
        long algorithm_auth;    // server authentication
        long algorithm_enc;     // symmetric encryption
        long algorithm_mac;     // symmetric authentication
        int min_tls;                // minimum SSL/TLS protocol version
        int max_tls;                // maximum SSL/TLS protocol version
        int min_dtls;               // minimum DTLS protocol version
        int max_dtls;               // maximum DTLS protocol version
        @Deprecated long algorithms;
        private long algStrength;
        long algorithm2;
        int algStrengthBits;
        int algBits;
        @Deprecated private long mask;
        @Deprecated private long algStrengthMask;

        private volatile String cipherSuite;    //???
        /*
         *     uint32_t valid;
    const char *name;           // text name 
    const char *stdname;        // RFC name 
    uint32_t id;                // id, 4 bytes, first is version 
    uint32_t algorithm_mkey;    // key exchange algorithm 
    uint32_t algorithm_auth;    // server authentication 
    uint32_t algorithm_enc;     // symmetric encryption 
    uint32_t algorithm_mac;     // symmetric authentication 
    int min_tls;                // minimum SSL/TLS protocol version 
    int max_tls;                // maximum SSL/TLS protocol version 
    int min_dtls;               // minimum DTLS protocol version 
    int max_dtls;               // maximum DTLS protocol version
    uint32_t algo_strength;     // strength and export flags     

         */
        //{0, SSL_TXT_ALL, NULL, 0, 0, 0, ~SSL_eNULL},
        Def(int valid, String name, String stdname, long id, long algorithm_mkey){
            this(valid, name, stdname, id, algorithm_mkey, 0, 0, 0);
        }
        Def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
                long algorithm_enc){
            this(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, 0);
        }
        Def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
                long algorithm_enc, long algorithm_mac){
            this(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, 0, 0, 0, 0, 0);
        }
        Def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
                long algorithm_enc, long algorithm_mac, int min_tls, int max_tls, int min_dtls, int max_dtls,
                long algo_strength){
            this(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, min_tls, max_tls, min_dtls, max_dtls,
                    algo_strength, 0, 0, 0);
        }
        //(int, String, String, long, long, long, long, long, int, int, int, long, long, long, int, int) is undefined
        Def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
                long algorithm_enc, long algorithm_mac, int min_tls, int max_tls, int min_dtls, int max_dtls,
                long algo_strength, long algorithm2, int strength_bits, int alg_bits){
            // this.valid = (byte) valid;
            this.name = name;
            this.stdname = stdname;
            // this.id = id;
            this.algorithm_mkey = algorithm_mkey;
            this.algorithm_auth = algorithm_auth;
            this.algorithm_enc = algorithm_enc;
            this.algorithm_mac = algorithm_mac;
            this.min_tls = min_tls; 
            this.max_tls = max_tls; 
            this.min_dtls = min_dtls; 
            this.max_dtls = max_dtls;
            this.algStrength = algo_strength;
            this.algorithm2 = algorithm2;
            this.algStrengthBits = strength_bits;
            this.algBits = alg_bits;
        }
        @Deprecated Def(int valid, String name, long id, long algorithms, long algo_strength, long algorithm2, int strength_bits, int alg_bits, long mask, long maskStrength) {
            //this.valid = (byte) valid;
            this.name = name;
            this.stdname = null;
            //this.id = id;
            this.algorithms = algorithms;
            this.algStrength = algo_strength;
            //this.algorithm2 = algorithm2;
            this.algStrengthBits = strength_bits;
            this.algBits = alg_bits;
            this.mask = mask;
            this.algStrengthMask = maskStrength;
        }

        Def(String name, long algorithms, long algo_strength, int strength_bits, int alg_bits, long mask, long maskStrength) {
            this.name = name;
            this.stdname = null;
            this.algorithms = algorithms;
            this.algStrength = algo_strength;
            this.algStrengthBits = strength_bits;
            this.algBits = alg_bits;
            this.mask = mask;
            this.algStrengthMask = maskStrength;
        }

        public String getCipherSuite() {
            return cipherSuite;
        }

        Def setCipherSuite(final String suite) {
            String cipherSuite = this.cipherSuite;
            if (cipherSuite == null) {
                synchronized (this) {
                    if (this.cipherSuite == null) {
                        this.cipherSuite = suite;
                        return this;
                    }
                }
                cipherSuite = suite;
            }
            if (suite.equals(cipherSuite)) return this;
            try {
                Def clone = (Def) super.clone();
                clone.cipherSuite = suite;
                return clone;
            }
            catch (CloneNotSupportedException e) {
                throw new AssertionError(e); // won't happen
            }
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }

        @Override
        public boolean equals(Object other) {
            if ( this == other ) return true;
            if ( other instanceof Def ) {
                return this.name.equals(((Def) other).name);
            }
            return false;
        }

        @Override
        public int compareTo(final Def that) {
            return this.algStrengthBits - that.algStrengthBits;
        }

        @Override
        public String toString() {
            return getClass().getSimpleName() + '@' +
                   Integer.toHexString(System.identityHashCode(this)) +
                   '<' + name + '>';
        }

        // from ssl_cipher_apply_rule
        public boolean matches(Def current) {
//            ma = mask & cp->algorithms;
//            ma_s = mask_strength & cp->algo_strength;
//
//            // Select: if none of the mask bit was met from the
//            // cipher or not all of the bits were met, the
//            // selection does not apply.
//            if (((ma == 0) && (ma_s == 0)) ||
//                ((ma & algorithms) != ma) ||
//                ((ma_s & algo_strength) != ma_s))
//                continue; // does not apply
//            }
            final long ma = this.mask & current.algorithms;
            final long ma_s = this.algStrengthMask & current.algStrength;
            if ( ( ma == 0 && ma_s == 0 ) ||
                 ( (ma & this.algorithms) != ma ) ||
                 ( (ma_s & this.algStrength) != ma_s) ) {
                return false;
            }
            return true;
        }

    }

    static Collection<Def> matchingCiphers(final String cipherString, final String[] all,
        final boolean setSuite) {
        final List<Def> matchedList = new LinkedList<Def>();
        Set<Def> removed = null;

        /*
         * If the rule_string begins with DEFAULT, apply the default rule
         * before using the (possibly available) additional rules.
         * (Matching OpenSSL behaviour)
         */
        int offset = 0;
        final String[] parts = cipherString.split("[:, ]+");
        if ( parts.length >= 1 && "DEFAULT".equals(parts[0]) ) {
            final Collection<Def> matching = matchingCiphers(SSL_DEFAULT_CIPHER_LIST, all, setSuite);
            matchedList.addAll(matching);
            offset = offset + 1;
        }

        for ( int i = offset; i < parts.length; i++ ) {
            final String part = parts[i];

            if ( part.equals("@STRENGTH") ) {
                Collections.sort(matchedList); continue;
            }

            int index = 0;
            switch ( part.charAt(0) ) {
                case '!': case '+': case '-': index++; break;
            }

            final Collection<Def> matching;
            final String[] defs = part.substring(index).split("[+]");
            if ( defs.length == 1 ) {
                matching = matchingExact(defs[0], all, setSuite);
            }
            else {
                matching = matching(defs, all, setSuite);
            }

            if ( matching != null ) {
                if ( index > 0 ) {
                    switch ( part.charAt(0) ) {
                        case '!':
                            matchedList.removeAll(matching);
                            if ( removed == null ) removed = new HashSet<Def>();
                            removed.addAll(matching);
                            break;
                        case '+': // '+' is for moving entry in the list
                            for ( final Def def : matching ) {
                                if ( removed == null || ! removed.contains(def) ) {
                                    if ( matchedList.remove(def) ) matchedList.add(def);
                                }
                            }
                            break;
                        case '-':
                            matchedList.removeAll(matching);
                            break;
                    }
                }
                else {
                    for ( final Def def : matching ) {
                        if ( removed == null || ! removed.contains(def) ) {
                            if ( ! matchedList.contains(def) ) matchedList.add(def);
                        }
                    }
                }
            }
        }

        return matchedList;
    }

    private static Collection<Def> matchingExact(final String name, final String[] all,
        final boolean setSuite) {
        Def pattern = Definitions.get(name);
        if ( pattern != null ) {
            return matchingPattern(pattern, all, true, setSuite);
        }
        else {
            Def cipher = CipherNames.get(name);
            if (cipher != null) {
                return Collections.singleton(cipher);
            }
        }
        return null; // Collections.emptyList();
    }

    private static Collection<Def> matching(final String[] defs, final String[] all,
        final boolean setSuite) {
        Collection<Def> matching = null;
        for ( final String name : defs ) {
            final Def pattern = Definitions.get(name);
            if ( pattern != null ) {
                if ( matching == null ) {
                    matching = matchingPattern(pattern, all, true, setSuite);
                }
                else {
                    matching.retainAll( matchingPattern(pattern, all, false, setSuite) );
                }
            }
        }
        return matching;
    }

    private static Collection<Def> matchingPattern(
        final Def pattern, final String[] all, final boolean useSet,
        final boolean setSuite) {
        final Collection<Def> matching;
        if ( useSet ) matching = new LinkedHashSet<Def>();
        else matching = new ArrayList<Def>(all.length);

        for ( final String entry : all ) {
            final String ossl = SuiteToOSSL.get(entry);
            if ( ossl != null ) {
                final Def def = CipherNames.get(ossl);
                if ( def != null && pattern.matches(def) ) {
                    if ( setSuite ) {
                        matching.add( def.setCipherSuite(entry) );
                    }
                    else {
                        matching.add( def );
                    }
                }
            }
        }
        return matching;
    }

    private final static Map<String, Def> Definitions;
    //private final static ArrayList<Def> Ciphers;
    private final static Map<String, Def> CipherNames;
    private final static Map<String, String> SuiteToOSSL;

    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey);
        Definitions.put(name, def);
    }
    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey, algorithm_auth, 0, 0);
        Definitions.put(name, def);
    }
    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
            long algorithm_enc){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, 0);
        Definitions.put(name, def);
    }
    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
            long algorithm_enc, long algorithm_mac){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, 0, 0, 0, 0, 0);
        Definitions.put(name, def);
    }
    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
            long algorithm_enc, long algorithm_mac, int min_tls){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, min_tls, 0, 0, 0, 0);
        Definitions.put(name, def);
    }
    private static void def(int valid, String name, String stdname, long id, long algorithm_mkey, long algorithm_auth,
            long algorithm_enc, long algorithm_mac, int min_tls, int max_tls, int min_dtls, int max_dtls,
            long algo_strength){
        Def def = new Def(valid, name, stdname, id, algorithm_mkey, algorithm_auth, algorithm_enc, algorithm_mac, 
                min_tls, max_tls, min_dtls, max_dtls, algo_strength);
        Definitions.put(name, def);
    }
    

    static {
        Definitions = new HashMap<String, Def>( 48, 1 );
        // TODO review base on OpenSSL's static const SSL_CIPHER cipher_aliases[] ?!
        // It seems that this list is based on OpenSSL 0.9.7
        /*
         * struct ssl_cipher_st {
                uint32_t valid;
                const char *name;           // text name 
                const char *stdname;        // RFC name 
                uint32_t id;                // id, 4 bytes, first is version 
                uint32_t algorithm_mkey;    // key exchange algorithm 
                uint32_t algorithm_auth;    // server authentication 
                uint32_t algorithm_enc;     // symmetric encryption 
                uint32_t algorithm_mac;     // symmetric authentication 
         */
        // {0, SSL_TXT_ALL, NULL, 0, 0, 0, ~SSL_eNULL},         1.1.1
        //  {0,SSL_TXT_ALL, 0,SSL_ALL & ~SSL_eNULL, SSL_ALL ,0,0,0,SSL_ALL,SSL_ALL},  0.9.7
        /*
         *
    {0, SSL_TXT_ALL, NULL, 0, 0, 0, ~SSL_eNULL},
    {0, SSL_TXT_CMPALL, NULL, 0, 0, 0, SSL_eNULL},
    {0, SSL_TXT_CMPDEF, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT},
    {0, SSL_TXT_kRSA, NULL, 0, SSL_kRSA},
    {0, SSL_TXT_kEDH, NULL, 0, SSL_kDHE},
    {0, SSL_TXT_kDHE, NULL, 0, SSL_kDHE},
    {0, SSL_TXT_DH, NULL, 0, SSL_kDHE},

         */
        def(0,SSL_TXT_ALL, null, 0, 0, 0, ~SSL_eNULL);
        def(0,SSL_TXT_ALL, null, 0, 0, 0, SSL_eNULL);
        def(0,SSL_TXT_CMPDEF, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_NOT_DEFAULT);
        def(0,SSL_TXT_kRSA, null, 0,SSL_kRSA);
        def(0,SSL_TXT_kEDH, null, 0,SSL_kDHE);
        def(0,SSL_TXT_kEDH, null, 0,SSL_kDHE);
        def(0,SSL_TXT_DH, null, 0,SSL_kDHE);
        
        /*
         * 
    {0, SSL_TXT_kEECDH, NULL, 0, SSL_kECDHE},
    {0, SSL_TXT_kECDHE, NULL, 0, SSL_kECDHE},
    {0, SSL_TXT_ECDH, NULL, 0, SSL_kECDHE},

    {0, SSL_TXT_kPSK, NULL, 0, SSL_kPSK},
    {0, SSL_TXT_kRSAPSK, NULL, 0, SSL_kRSAPSK},
    {0, SSL_TXT_kECDHEPSK, NULL, 0, SSL_kECDHEPSK},
    {0, SSL_TXT_kDHEPSK, NULL, 0, SSL_kDHEPSK},
    {0, SSL_TXT_kSRP, NULL, 0, SSL_kSRP},
    {0, SSL_TXT_kGOST, NULL, 0, SSL_kGOST},

         */

        def(0, SSL_TXT_kEECDH, null, 0,SSL_kECDHE);
        def(0, SSL_TXT_kECDHE, null, 0,SSL_kECDHE);
        def(0, SSL_TXT_ECDH, null, 0,SSL_kECDHE);
        
        def(0, SSL_TXT_kPSK, null, 0, SSL_kPSK);
        def(0, SSL_TXT_kRSAPSK, null, 0, SSL_kRSAPSK);
        def(0, SSL_TXT_kECDHEPSK, null, 0, SSL_kECDHEPSK);
        def(0, SSL_TXT_kDHEPSK, null, 0, SSL_kDHEPSK);
        def(0, SSL_TXT_kSRP, null, 0, SSL_kSRP);
        def(0, SSL_TXT_kGOST, null, 0, SSL_kGOST);

        /* server authentication aliases */
        def(0, SSL_TXT_aRSA, null, 0, 0, SSL_aRSA);
        def(0, SSL_TXT_aDSS, null, 0, 0, SSL_aDSS);
        def(0, SSL_TXT_DSS, null, 0, 0, SSL_aDSS);
        def(0, SSL_TXT_aNULL, null, 0, 0, SSL_aNULL);
        def(0, SSL_TXT_aECDSA, null, 0, 0, SSL_aECDSA);
        def(0, SSL_TXT_ECDSA, null, 0, 0, SSL_aECDSA);
        def(0, SSL_TXT_aPSK, null, 0, 0, SSL_aPSK);
        def(0, SSL_TXT_aGOST01, null, 0, 0, SSL_aGOST01);
        def(0, SSL_TXT_aGOST12, null, 0, 0, SSL_aGOST12);
        def(0, SSL_TXT_aGOST, null, 0, 0, SSL_aGOST01 | SSL_aGOST12);
        def(0, SSL_TXT_aSRP, null, 0, 0, SSL_aSRP);

        /* aliases combining key exchange and server authentication */
        def(0, SSL_TXT_EDH, null, 0, SSL_kDHE, ~SSL_aNULL);
        def(0, SSL_TXT_DHE, null, 0, SSL_kDHE, ~SSL_aNULL);
        def(0, SSL_TXT_EECDH, null, 0, SSL_kECDHE, ~SSL_aNULL);
        def(0, SSL_TXT_ECDHE, null, 0, SSL_kECDHE, ~SSL_aNULL);
        def(0, SSL_TXT_NULL, null, 0, 0, 0, SSL_eNULL);
        def(0, SSL_TXT_RSA, null, 0, SSL_kRSA, SSL_aRSA);
        def(0, SSL_TXT_ADH, null, 0, SSL_kDHE, SSL_aNULL);
        def(0, SSL_TXT_AECDH, null, 0, SSL_kECDHE, SSL_aNULL);
        def(0, SSL_TXT_PSK, null, 0, SSL_PSK);
        def(0, SSL_TXT_SRP, null, 0, SSL_kSRP);

        /* symmetric encryption aliases */
        def(0, SSL_TXT_3DES, null, 0, 0, 0, SSL_3DES);
        def(0, SSL_TXT_RC4, null, 0, 0, 0, SSL_RC4);
        def(0, SSL_TXT_RC2, null, 0, 0, 0, SSL_RC2);
        def(0, SSL_TXT_IDEA, null, 0, 0, 0, SSL_IDEA);
        def(0, SSL_TXT_SEED, null, 0, 0, 0, SSL_SEED);
        def(0, SSL_TXT_eNULL, null, 0, 0, 0, SSL_eNULL);
        def(0, SSL_TXT_GOST, null, 0, 0, 0, SSL_eGOST2814789CNT | SSL_eGOST2814789CNT12);
        def(0, SSL_TXT_AES128, null, 0, 0, 0,
         SSL_AES128 | SSL_AES128GCM | SSL_AES128CCM | SSL_AES128CCM8);
        def(0, SSL_TXT_AES256, null, 0, 0, 0,
         SSL_AES256 | SSL_AES256GCM | SSL_AES256CCM | SSL_AES256CCM8);
        def(0, SSL_TXT_AES, null, 0, 0, 0, SSL_AES);
        def(0, SSL_TXT_AES_GCM, null, 0, 0, 0, SSL_AES128GCM | SSL_AES256GCM);
        def(0, SSL_TXT_AES_CCM, null, 0, 0, 0,
         SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8);
        def(0, SSL_TXT_AES_CCM_8, null, 0, 0, 0, SSL_AES128CCM8 | SSL_AES256CCM8);
        def(0, SSL_TXT_CAMELLIA128, null, 0, 0, 0, SSL_CAMELLIA128);
        def(0, SSL_TXT_CAMELLIA256, null, 0, 0, 0, SSL_CAMELLIA256);
        def(0, SSL_TXT_CAMELLIA, null, 0, 0, 0, SSL_CAMELLIA);
        def(0, SSL_TXT_CHACHA20, null, 0, 0, 0, SSL_CHACHA20);

        def(0, SSL_TXT_ARIA, null, 0, 0, 0, SSL_ARIA);
        def(0, SSL_TXT_ARIA_GCM, null, 0, 0, 0, SSL_ARIA128GCM | SSL_ARIA256GCM);
        def(0, SSL_TXT_ARIA128, null, 0, 0, 0, SSL_ARIA128GCM);
        def(0, SSL_TXT_ARIA256, null, 0, 0, 0, SSL_ARIA256GCM);
        
        /* MAC aliases */
        def(0, SSL_TXT_MD5, null, 0, 0, 0, 0, SSL_MD5);
        def(0, SSL_TXT_SHA1, null, 0, 0, 0, 0, SSL_SHA1);
        def(0, SSL_TXT_SHA, null, 0, 0, 0, 0, SSL_SHA1);
        def(0, SSL_TXT_GOST94, null, 0, 0, 0, 0, SSL_GOST94);
        def(0, SSL_TXT_GOST89MAC, null, 0, 0, 0, 0, SSL_GOST89MAC | SSL_GOST89MAC12);
        def(0, SSL_TXT_SHA256, null, 0, 0, 0, 0, SSL_SHA256);
        def(0, SSL_TXT_SHA384, null, 0, 0, 0, 0, SSL_SHA384);
        def(0, SSL_TXT_GOST12, null, 0, 0, 0, 0, SSL_GOST12_256);

        /* protocol version aliases */
        def(0, SSL_TXT_SSLV3, null, 0, 0, 0, 0, 0, SSL.SSL3_VERSION);
        def(0, SSL_TXT_TLSV1, null, 0, 0, 0, 0, 0, SSL.TLS1_VERSION);
        def(0, "TLSv1.0", null, 0, 0, 0, 0, 0, SSL.TLS1_VERSION);
        def(0, SSL_TXT_TLSV1_2, null, 0, 0, 0, 0, 0, SSL.TLS1_2_VERSION);

        /* strength classes */
        def(0, SSL_TXT_LOW, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_LOW);
        def(0, SSL_TXT_MEDIUM, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_MEDIUM);
        def(0, SSL_TXT_HIGH, null, 0, 0, 0, 0, 0, 0, 0, 0, 0, SSL_HIGH);
        /* FIPS 140-2 approved ciphersuite */
        def(0, SSL_TXT_FIPS, null, 0, 0, 0, ~SSL_eNULL, 0, 0, 0, 0, 0, SSL_FIPS);

        /* "EDH-" aliases to "DHE-" labels (for backward compatibility) */
        def(0, SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA, null, 0,
         SSL_kDHE, SSL_aDSS, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS);
        def(0, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA, null, 0,
         SSL_kDHE, SSL_aRSA, SSL_3DES, SSL_SHA1, 0, 0, 0, 0, SSL_HIGH | SSL_FIPS);

        final ArrayList<Def> Ciphers = new ArrayList<Def>( 96 );
        /** OPENSSL 1.1.1 example:
         * static SSL_CIPHER ssl3_ciphers[] = {
            {
             1,
             SSL3_TXT_RSA_NULL_MD5,
             SSL3_RFC_RSA_NULL_MD5,
             SSL3_CK_RSA_NULL_MD5,
             SSL_kRSA,
             SSL_aRSA,
             SSL_eNULL,
             SSL_MD5,
             SSL3_VERSION, TLS1_2_VERSION,
             DTLS1_BAD_VER, DTLS1_2_VERSION,
             SSL_STRONG_NONE,
             SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
             0,
             0,
             },
             
            // OpenSSL up to 1.0.2u is "OR'ing" like below 
            {
            1,
            SSL3_TXT_RSA_NULL_MD5,
            SSL3_CK_RSA_NULL_MD5,
            SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_MD5|SSL_SSLV3,
            SSL_NOT_EXP|SSL_STRONG_NONE,
            0,
            0,
            0,
            SSL_ALL_CIPHERS,
            SSL_ALL_STRENGTHS,
            },
         */
        Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_NULL_MD5,
            SSL3_RFC_RSA_NULL_MD5,
            SSL3_CK_RSA_NULL_MD5,
            SSL_kRSA,
            SSL_aRSA,
            SSL_eNULL,
            SSL_MD5,
            SSL.SSL3_VERSION, SSL.TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
        ));
        Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_NULL_SHA,
            SSL3_RFC_RSA_NULL_SHA,
            SSL3_CK_RSA_NULL_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA1,
            SSL.SSL3_VERSION, SSL.TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0));
        
        Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_DES_192_CBC3_SHA,
            SSL3_RFC_RSA_DES_192_CBC3_SHA,
            SSL3_CK_RSA_DES_192_CBC3_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
           Ciphers.add(new Def(
            1,
            SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA,
            SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA,
            SSL3_CK_DHE_DSS_DES_192_CBC3_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
           Ciphers.add(new Def(
            1,
            SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA,
            SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA,
            SSL3_CK_DHE_RSA_DES_192_CBC3_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
           Ciphers.add(new Def(
            1,
            SSL3_TXT_ADH_DES_192_CBC_SHA,
            SSL3_RFC_ADH_DES_192_CBC_SHA,
            SSL3_CK_ADH_DES_192_CBC_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
       //#endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_128_SHA,
            TLS1_RFC_RSA_WITH_AES_128_SHA,
            TLS1_CK_RSA_WITH_AES_128_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
            TLS1_RFC_DHE_DSS_WITH_AES_128_SHA,
            TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
            TLS1_RFC_DHE_RSA_WITH_AES_128_SHA,
            TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_128_SHA,
            TLS1_RFC_ADH_WITH_AES_128_SHA,
            TLS1_CK_ADH_WITH_AES_128_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_256_SHA,
            TLS1_RFC_RSA_WITH_AES_256_SHA,
            TLS1_CK_RSA_WITH_AES_256_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
            TLS1_RFC_DHE_DSS_WITH_AES_256_SHA,
            TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
            TLS1_RFC_DHE_RSA_WITH_AES_256_SHA,
            TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_256_SHA,
            TLS1_RFC_ADH_WITH_AES_256_SHA,
            TLS1_CK_ADH_WITH_AES_256_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_NULL_SHA256,
            TLS1_RFC_RSA_WITH_NULL_SHA256,
            TLS1_CK_RSA_WITH_NULL_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_128_SHA256,
            TLS1_RFC_RSA_WITH_AES_128_SHA256,
            TLS1_CK_RSA_WITH_AES_128_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_256_SHA256,
            TLS1_RFC_RSA_WITH_AES_256_SHA256,
            TLS1_CK_RSA_WITH_AES_256_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
            TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256,
            TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
            TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256,
            TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
            TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256,
            TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
            TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256,
            TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_128_SHA256,
            TLS1_RFC_ADH_WITH_AES_128_SHA256,
            TLS1_CK_ADH_WITH_AES_128_SHA256,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_256_SHA256,
            TLS1_RFC_ADH_WITH_AES_256_SHA256,
            TLS1_CK_ADH_WITH_AES_256_SHA256,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256,
            TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384,
            TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
            SSL_kDHE,
            SSL_aDSS,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256,
            TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384,
            TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
            SSL_kDHE,
            SSL_aNULL,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_128_CCM,
            TLS1_RFC_RSA_WITH_AES_128_CCM,
            TLS1_CK_RSA_WITH_AES_128_CCM,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES128CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_256_CCM,
            TLS1_RFC_RSA_WITH_AES_256_CCM,
            TLS1_CK_RSA_WITH_AES_256_CCM,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES256CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_128_CCM,
            TLS1_RFC_DHE_RSA_WITH_AES_128_CCM,
            TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES128CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_256_CCM,
            TLS1_RFC_DHE_RSA_WITH_AES_256_CCM,
            TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES256CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_128_CCM_8,
            TLS1_RFC_RSA_WITH_AES_128_CCM_8,
            TLS1_CK_RSA_WITH_AES_128_CCM_8,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES128CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_AES_256_CCM_8,
            TLS1_RFC_RSA_WITH_AES_256_CCM_8,
            TLS1_CK_RSA_WITH_AES_256_CCM_8,
            SSL_kRSA,
            SSL_aRSA,
            SSL_AES256CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8,
            TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8,
            TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES128CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8,
            TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8,
            TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8,
            SSL_kDHE,
            SSL_aRSA,
            SSL_AES256CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_128_CCM,
            TLS1_RFC_PSK_WITH_AES_128_CCM,
            TLS1_CK_PSK_WITH_AES_128_CCM,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES128CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_256_CCM,
            TLS1_RFC_PSK_WITH_AES_256_CCM,
            TLS1_CK_PSK_WITH_AES_256_CCM,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES256CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_128_CCM,
            TLS1_RFC_DHE_PSK_WITH_AES_128_CCM,
            TLS1_CK_DHE_PSK_WITH_AES_128_CCM,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES128CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_256_CCM,
            TLS1_RFC_DHE_PSK_WITH_AES_256_CCM,
            TLS1_CK_DHE_PSK_WITH_AES_256_CCM,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES256CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_128_CCM_8,
            TLS1_RFC_PSK_WITH_AES_128_CCM_8,
            TLS1_CK_PSK_WITH_AES_128_CCM_8,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES128CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_256_CCM_8,
            TLS1_RFC_PSK_WITH_AES_256_CCM_8,
            TLS1_CK_PSK_WITH_AES_256_CCM_8,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES256CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8,
            TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8,
            TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES128CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8,
            TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8,
            TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES256CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES128CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES256CCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES128CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES256CCM8,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
            TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA,
            TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_eNULL,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
       //# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
            TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
            TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_3DES,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
       //# endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES128,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES256,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
            TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA,
            TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
       //# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
            TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
            TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_3DES,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
       //# endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
            TLS1_RFC_ECDH_anon_WITH_NULL_SHA,
            TLS1_CK_ECDH_anon_WITH_NULL_SHA,
            SSL_kECDHE,
            SSL_aNULL,
            SSL_eNULL,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
       //# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
            TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA,
            TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
            SSL_kECDHE,
            SSL_aNULL,
            SSL_3DES,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
       //# endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
            TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA,
            TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
            SSL_kECDHE,
            SSL_aNULL,
            SSL_AES128,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
            TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA,
            TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
            SSL_kECDHE,
            SSL_aNULL,
            SSL_AES256,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES256,
            SSL_SHA384,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
            TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256,
            TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
            TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384,
            TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA384,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_NULL_SHA,
            TLS1_RFC_PSK_WITH_NULL_SHA,
            TLS1_CK_PSK_WITH_NULL_SHA,
            SSL_kPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_NULL_SHA,
            TLS1_RFC_DHE_PSK_WITH_NULL_SHA,
            TLS1_CK_DHE_PSK_WITH_NULL_SHA,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_NULL_SHA,
            TLS1_RFC_RSA_PSK_WITH_NULL_SHA,
            TLS1_CK_RSA_PSK_WITH_NULL_SHA,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0
            ));
       //# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
            SSL_kPSK,
            SSL_aPSK,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168
            ));
       //# endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
            TLS1_RFC_PSK_WITH_AES_128_CBC_SHA,
            TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
            TLS1_RFC_PSK_WITH_AES_256_CBC_SHA,
            TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256
            ));
       //# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
       # endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA,
            TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA,
            TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA,
            TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA,
            TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
       # ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
       # endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA,
            TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA,
            TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA,
            TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA,
            TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_CK_PSK_WITH_AES_128_GCM_SHA256,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_CK_PSK_WITH_AES_256_GCM_SHA384,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256,
            TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384,
            TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_CK_PSK_WITH_AES_128_CBC_SHA256,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_CK_PSK_WITH_AES_256_CBC_SHA384,
            SSL_kPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_NULL_SHA256,
            TLS1_RFC_PSK_WITH_NULL_SHA256,
            TLS1_CK_PSK_WITH_NULL_SHA256,
            SSL_kPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_NULL_SHA384,
            TLS1_RFC_PSK_WITH_NULL_SHA384,
            TLS1_CK_PSK_WITH_NULL_SHA384,
            SSL_kPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_NULL_SHA256,
            TLS1_RFC_DHE_PSK_WITH_NULL_SHA256,
            TLS1_CK_DHE_PSK_WITH_NULL_SHA256,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_NULL_SHA384,
            TLS1_RFC_DHE_PSK_WITH_NULL_SHA384,
            TLS1_CK_DHE_PSK_WITH_NULL_SHA384,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_NULL_SHA256,
            TLS1_RFC_RSA_PSK_WITH_NULL_SHA256,
            TLS1_CK_RSA_PSK_WITH_NULL_SHA256,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_NULL_SHA384,
            TLS1_RFC_RSA_PSK_WITH_NULL_SHA384,
            TLS1_CK_RSA_PSK_WITH_NULL_SHA384,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_eNULL,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            0,
            0,
            ));
       #  ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_3DES,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
       #  endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_AES128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_AES256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA,
            TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA,
            TLS1_CK_ECDHE_PSK_WITH_NULL_SHA,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256,
            TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256,
            TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384,
            TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384,
            TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_eNULL,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_STRONG_NONE | SSL_FIPS,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            0,
            0,
            ));

       # ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
            SSL_kSRP,
            SSL_aSRP,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
            SSL_kSRP,
            SSL_aRSA,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
            TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
            TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
            SSL_kSRP,
            SSL_aDSS,
            SSL_3DES,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            112,
            168,
            ));
       # endif
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
            TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA,
            TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
            SSL_kSRP,
            SSL_aSRP,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
            SSL_kSRP,
            SSL_aRSA,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
            SSL_kSRP,
            SSL_aDSS,
            SSL_AES128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
            TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA,
            TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
            SSL_kSRP,
            SSL_aSRP,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
            SSL_kSRP,
            SSL_aRSA,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
            SSL_kSRP,
            SSL_aDSS,
            SSL_AES256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));

       #if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
            TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305,
            TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
            SSL_kDHE,
            SSL_aRSA,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_CHACHA20_POLY1305,
            TLS1_RFC_PSK_WITH_CHACHA20_POLY1305,
            TLS1_CK_PSK_WITH_CHACHA20_POLY1305,
            SSL_kPSK,
            SSL_aPSK,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305,
            TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305,
            TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305,
            TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305,
            TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305,
            TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305,
            TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_CHACHA20POLY1305,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
       #endif                          /* !defined(OPENSSL_NO_CHACHA) &&
                                        * !defined(OPENSSL_NO_POLY1305) */

       #ifndef OPENSSL_NO_CAMELLIA
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kEDH,
            SSL_aDSS,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kEDH,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kEDH,
            SSL_aNULL,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
            SSL_kEDH,
            SSL_aDSS,
            SSL_CAMELLIA256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
            SSL_kEDH,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256,
            TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256,
            SSL_kEDH,
            SSL_aNULL,
            SSL_CAMELLIA256,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_CAMELLIA256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA,
            TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_CAMELLIA256,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_CAMELLIA128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA,
            TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_CAMELLIA128,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kPSK,
            SSL_aPSK,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kPSK,
            SSL_aPSK,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_CAMELLIA128,
            SSL_SHA256,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_CAMELLIA256,
            SSL_SHA384,
            TLS1_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
       #endif                          /* OPENSSL_NO_CAMELLIA */

       #ifndef OPENSSL_NO_GOST
           Ciphers.add(new Def(
            1,
            "GOST2001-GOST89-GOST89",
            "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
            0x3000081,
            SSL_kGOST,
            SSL_aGOST01,
            SSL_eGOST2814789CNT,
            SSL_GOST89MAC,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            "GOST2001-NULL-GOST94",
            "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
            0x3000083,
            SSL_kGOST,
            SSL_aGOST01,
            SSL_eNULL,
            SSL_GOST94,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_STRONG_NONE,
            SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
            0,
            0,
            ));
           Ciphers.add(new Def(
            1,
            "GOST2012-GOST8912-GOST8912",
            NULL,
            0x0300ff85,
            SSL_kGOST,
            SSL_aGOST12 | SSL_aGOST01,
            SSL_eGOST2814789CNT12,
            SSL_GOST89MAC12,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_HIGH,
            SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            "GOST2012-NULL-GOST12",
            NULL,
            0x0300ff87,
            SSL_kGOST,
            SSL_aGOST12 | SSL_aGOST01,
            SSL_eNULL,
            SSL_GOST12_256,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_STRONG_NONE,
            SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
            0,
            0,
            ));
       #endif                          /* OPENSSL_NO_GOST */

       #ifndef OPENSSL_NO_IDEA
           Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_IDEA_128_SHA,
            SSL3_RFC_RSA_IDEA_128_SHA,
            SSL3_CK_RSA_IDEA_128_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_IDEA,
            SSL_SHA1,
            SSL3_VERSION, TLS1_1_VERSION,
            DTLS1_BAD_VER, DTLS1_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
       #endif

       #ifndef OPENSSL_NO_SEED
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_SEED_SHA,
            TLS1_RFC_RSA_WITH_SEED_SHA,
            TLS1_CK_RSA_WITH_SEED_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_SEED,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
            TLS1_RFC_DHE_DSS_WITH_SEED_SHA,
            TLS1_CK_DHE_DSS_WITH_SEED_SHA,
            SSL_kDHE,
            SSL_aDSS,
            SSL_SEED,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
            TLS1_RFC_DHE_RSA_WITH_SEED_SHA,
            TLS1_CK_DHE_RSA_WITH_SEED_SHA,
            SSL_kDHE,
            SSL_aRSA,
            SSL_SEED,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ADH_WITH_SEED_SHA,
            TLS1_RFC_ADH_WITH_SEED_SHA,
            TLS1_CK_ADH_WITH_SEED_SHA,
            SSL_kDHE,
            SSL_aNULL,
            SSL_SEED,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            DTLS1_BAD_VER, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
       #endif                          /* OPENSSL_NO_SEED */

       #ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
           Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_RC4_128_MD5,
            SSL3_RFC_RSA_RC4_128_MD5,
            SSL3_CK_RSA_RC4_128_MD5,
            SSL_kRSA,
            SSL_aRSA,
            SSL_RC4,
            SSL_MD5,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            SSL3_TXT_RSA_RC4_128_SHA,
            SSL3_RFC_RSA_RC4_128_SHA,
            SSL3_CK_RSA_RC4_128_SHA,
            SSL_kRSA,
            SSL_aRSA,
            SSL_RC4,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            SSL3_TXT_ADH_RC4_128_MD5,
            SSL3_RFC_ADH_RC4_128_MD5,
            SSL3_CK_ADH_RC4_128_MD5,
            SSL_kDHE,
            SSL_aNULL,
            SSL_RC4,
            SSL_MD5,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA,
            TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA,
            TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA,
            SSL_kECDHEPSK,
            SSL_aPSK,
            SSL_RC4,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
            TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA,
            TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
            SSL_kECDHE,
            SSL_aNULL,
            SSL_RC4,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
            TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA,
            TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_RC4,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
            TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA,
            TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_RC4,
            SSL_SHA1,
            TLS1_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_RC4_128_SHA,
            TLS1_RFC_PSK_WITH_RC4_128_SHA,
            TLS1_CK_PSK_WITH_RC4_128_SHA,
            SSL_kPSK,
            SSL_aPSK,
            SSL_RC4,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA,
            TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA,
            TLS1_CK_RSA_PSK_WITH_RC4_128_SHA,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_RC4,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA,
            TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA,
            TLS1_CK_DHE_PSK_WITH_RC4_128_SHA,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_RC4,
            SSL_SHA1,
            SSL3_VERSION, TLS1_2_VERSION,
            0, 0,
            SSL_NOT_DEFAULT | SSL_MEDIUM,
            SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
            128,
            128,
            ));
       #endif                          /* OPENSSL_NO_WEAK_SSL_CIPHERS */

       #ifndef OPENSSL_NO_ARIA
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256,
            SSL_kRSA,
            SSL_aRSA,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384,
            SSL_kRSA,
            SSL_aRSA,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
            SSL_kDHE,
            SSL_aRSA,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
            SSL_kDHE,
            SSL_aRSA,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
            SSL_kDHE,
            SSL_aDSS,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
            SSL_kDHE,
            SSL_aDSS,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
            SSL_kECDHE,
            SSL_aECDSA,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
            SSL_kECDHE,
            SSL_aRSA,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256,
            SSL_kPSK,
            SSL_aPSK,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384,
            SSL_kPSK,
            SSL_aPSK,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
            SSL_kDHEPSK,
            SSL_aPSK,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
            TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_ARIA128GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
            128,
            128,
            ));
           Ciphers.add(new Def(
            1,
            TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
            TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
            SSL_kRSAPSK,
            SSL_aRSA,
            SSL_ARIA256GCM,
            SSL_AEAD,
            TLS1_2_VERSION, TLS1_2_VERSION,
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            SSL_NOT_DEFAULT | SSL_HIGH,
            SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
            256,
            256,
            ));

        /* Cipher 01 */
        
        
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_NULL_MD5,
                            SSL3_CK_RSA_NULL_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_MD5|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 02 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_NULL_SHA,
                            SSL3_CK_RSA_NULL_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_eNULL |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 03 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_40_MD5,
                            SSL3_CK_RSA_RC4_40_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 04 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_128_MD5,
                            SSL3_CK_RSA_RC4_128_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_MD5|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 05 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC4_128_SHA,
                            SSL3_CK_RSA_RC4_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_RC4  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 06 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_RC2_40_MD5,
                            SSL3_CK_RSA_RC2_40_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC2  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 07 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_IDEA_128_SHA,
                            SSL3_CK_RSA_IDEA_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_IDEA |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 08 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_40_CBC_SHA,
                            SSL3_CK_RSA_DES_40_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 09 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_64_CBC_SHA,
                            SSL3_CK_RSA_DES_64_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0A */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_RSA_DES_192_CBC3_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* The DH ciphers */
        /* Cipher 0B */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
                            SSL3_CK_DH_DSS_DES_40_CBC_SHA,
                            SSL_kDHd |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0C */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
                            SSL3_CK_DH_DSS_DES_64_CBC_SHA,
                            SSL_kDHd |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0D */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
                            SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
                            SSL_kDHd |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0E */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
                            SSL3_CK_DH_RSA_DES_40_CBC_SHA,
                            SSL_kDHr |SSL_aDH|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 0F */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
                            SSL3_CK_DH_RSA_DES_64_CBC_SHA,
                            SSL_kDHr |SSL_aDH|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 10 */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
                            SSL_kDHr |SSL_aDH|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* The Ephemeral DH ciphers */
        /* Cipher 11 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
                            SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 12 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
                            SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 13 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
                            SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 14 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
                            SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 15 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
                            SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 16 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
                            SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 17 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_RC4_40_MD5,
                            SSL3_CK_ADH_RC4_40_MD5,
                            SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 18 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_RC4_128_MD5,
                            SSL3_CK_ADH_RC4_128_MD5,
                            SSL_kEDH |SSL_aNULL|SSL_RC4  |SSL_MD5 |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 19 */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_40_CBC_SHA,
                            SSL3_CK_ADH_DES_40_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_DES|SSL_SHA1|SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 1A */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_64_CBC_SHA,
                            SSL3_CK_ADH_DES_64_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_DES  |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 1B */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_ADH_DES_192_CBC_SHA,
                            SSL3_CK_ADH_DES_192_CBC_SHA,
                            SSL_kEDH |SSL_aNULL|SSL_3DES |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Fortezza */
        /* Cipher 1C */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_FZA_DMS_NULL_SHA,
                            SSL3_CK_FZA_DMS_NULL_SHA,
                            SSL_kFZA|SSL_aFZA |SSL_eNULL |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1D */
        Ciphers.add(new Def(
                            0,
                            SSL3_TXT_FZA_DMS_FZA_SHA,
                            SSL3_CK_FZA_DMS_FZA_SHA,
                            SSL_kFZA|SSL_aFZA |SSL_eFZA |SSL_SHA1|SSL_SSLV3,
                            SSL_NOT_EXP|SSL_STRONG_NONE,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1E VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_64_CBC_SHA,
                            SSL3_CK_KRB5_DES_64_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_SHA1   |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 1F VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_192_CBC3_SHA,
                            SSL3_CK_KRB5_DES_192_CBC3_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_3DES|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            112,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 20 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_128_SHA,
                            SSL3_CK_KRB5_RC4_128_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 21 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_IDEA_128_CBC_SHA,
                            SSL3_CK_KRB5_IDEA_128_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_IDEA|SSL_SHA1  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 22 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_64_CBC_MD5,
                            SSL3_CK_KRB5_DES_64_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_MD5    |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_LOW,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 23 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_192_CBC3_MD5,
                            SSL3_CK_KRB5_DES_192_CBC3_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_3DES|SSL_MD5   |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            112,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 24 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_128_MD5,
                            SSL3_CK_KRB5_RC4_128_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_MD5  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 25 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_IDEA_128_CBC_MD5,
                            SSL3_CK_KRB5_IDEA_128_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_IDEA|SSL_MD5  |SSL_SSLV3,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 26 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_40_CBC_SHA,
                            SSL3_CK_KRB5_DES_40_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 27 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC2_40_CBC_SHA,
                            SSL3_CK_KRB5_RC2_40_CBC_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC2|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 28 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_40_SHA,
                            SSL3_CK_KRB5_RC4_40_SHA,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_SHA1   |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 29 VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_DES_40_CBC_MD5,
                            SSL3_CK_KRB5_DES_40_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_DES|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2A VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC2_40_CBC_MD5,
                            SSL3_CK_KRB5_RC2_40_CBC_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC2|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            40,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2B VRS */
        Ciphers.add(new Def(
                            1,
                            SSL3_TXT_KRB5_RC4_40_MD5,
                            SSL3_CK_KRB5_RC4_40_MD5,
                            SSL_kKRB5|SSL_aKRB5|  SSL_RC4|SSL_MD5    |SSL_SSLV3,
                            SSL_EXPORT|SSL_EXP40,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 2F */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_WITH_AES_128_SHA,
                            TLS1_CK_RSA_WITH_AES_128_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA |SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 30 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_DSS_WITH_AES_128_SHA,
                            TLS1_CK_DH_DSS_WITH_AES_128_SHA,
                            SSL_kDHd|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 31 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_RSA_WITH_AES_128_SHA,
                            TLS1_CK_DH_RSA_WITH_AES_128_SHA,
                            SSL_kDHr|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 32 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
                            TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 33 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
                            TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 34 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ADH_WITH_AES_128_SHA,
                            TLS1_CK_ADH_WITH_AES_128_SHA,
                            SSL_kEDH|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher 35 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_WITH_AES_256_SHA,
                            TLS1_CK_RSA_WITH_AES_256_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_AES|SSL_SHA |SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 36 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_DSS_WITH_AES_256_SHA,
                            TLS1_CK_DH_DSS_WITH_AES_256_SHA,
                            SSL_kDHd|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 37 */
        Ciphers.add(new Def(
                            0,
                            TLS1_TXT_DH_RSA_WITH_AES_256_SHA,
                            TLS1_CK_DH_RSA_WITH_AES_256_SHA,
                            SSL_kDHr|SSL_aDH|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 38 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
                            TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 39 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
                            TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 3A */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ADH_WITH_AES_256_SHA,
                            TLS1_CK_ADH_WITH_AES_256_SHA,
                            SSL_kEDH|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            256,
                            256,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* New TLS Export CipherSuites */
        /* Cipher 60 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_MD5|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 61 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
                            SSL_kRSA|SSL_aRSA|SSL_RC2|SSL_MD5|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 62 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                            TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_DES|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 63 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                            TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_DES|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            56,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 64 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA,
                            TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA,
                            SSL_kRSA|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 65 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
                            TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_EXPORT|SSL_EXP56,
                            0,
                            56,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher 66 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA,
                            TLS1_CK_DHE_DSS_WITH_RC4_128_SHA,
                            SSL_kEDH|SSL_aDSS|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_MEDIUM,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));
        /* Cipher C001 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C002 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C003 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDH|SSL_aECDSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C006 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C007 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C008 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDHE|SSL_aECDSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00B */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_NULL_SHA,
                            TLS1_CK_ECDH_RSA_WITH_NULL_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00C */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C00D */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDH|SSL_aRSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C010 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C011 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_RC4|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            128,
                            128,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C012 */
	    Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
                            TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
                            SSL_kECDHE|SSL_aRSA|SSL_3DES|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP|SSL_HIGH,
                            0,
                            168,
                            168,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        /* Cipher C015 */
        Ciphers.add(new Def(
                            1,
                            TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
                            TLS1_CK_ECDH_anon_WITH_NULL_SHA,
                            SSL_kECDHE|SSL_aNULL|SSL_eNULL|SSL_SHA|SSL_TLSV1,
                            SSL_NOT_EXP,
                            0,
                            0,
                            0,
                            SSL_ALL_CIPHERS,
                            SSL_ALL_STRENGTHS
                            ));

        String name;
        CipherNames = new HashMap<String, Def>(Ciphers.size() + 64, 1);

        SuiteToOSSL = new HashMap<String, String>( 120, 1 );
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_MD5", "NULL-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_SHA", "NULL-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_RC4_40_MD5", "EXP-RC4-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_RC4_128_MD5", "RC4-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_RC4_128_SHA", "RC4-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5","EXP-RC2-CBC-MD5");
        SuiteToOSSL.put("SSL_RSA_WITH_IDEA_CBC_SHA","IDEA-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_DES_CBC_SHA", "DES-CBC-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_DES_CBC_SHA", "EDH-DSS-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXP-EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_DES_CBC_SHA", "EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "EDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", "EXP-ADH-RC4-MD5");
        SuiteToOSSL.put("SSL_DH_anon_WITH_RC4_128_MD5", "ADH-RC4-MD5");
        SuiteToOSSL.put("SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", "EXP-ADH-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_DES_CBC_SHA", "ADH-DES-CBC-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", "ADH-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_MD5","NULL-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_SHA","NULL-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_RC4_40_MD5","EXP-RC4-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_RC4_128_MD5","RC4-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_RC4_128_SHA","RC4-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5","EXP-RC2-CBC-MD5");
        SuiteToOSSL.put("TLS_RSA_WITH_IDEA_CBC_SHA","IDEA-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA","EXP-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_DES_CBC_SHA","DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA","DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA","EXP-EDH-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_DES_CBC_SHA","EDH-DSS-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA","EDH-DSS-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA","EXP-EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_DES_CBC_SHA","EDH-RSA-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA","EDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5","EXP-ADH-RC4-MD5");
        SuiteToOSSL.put("TLS_DH_anon_WITH_RC4_128_MD5","ADH-RC4-MD5");
        SuiteToOSSL.put("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA","EXP-ADH-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_DES_CBC_SHA","ADH-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA","ADH-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA");
        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA");
        SuiteToOSSL.put("TLS_DH_DSS_WITH_AES_128_CBC_SHA","DH-DSS-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_DSS_WITH_AES_256_CBC_SHA","DH-DSS-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_RSA_WITH_AES_128_CBC_SHA","DH-RSA-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_RSA_WITH_AES_256_CBC_SHA","DH-RSA-AES256-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS-AES128-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS-AES256-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA");
        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_128_CBC_SHA", "ADH-AES128-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_256_CBC_SHA", "ADH-AES256-SHA");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_128_CBC_SHA256", "ADH-AES128-SHA256");
        SuiteToOSSL.put("TLS_DH_anon_WITH_AES_256_CBC_SHA256", "ADH-AES256-SHA256");
        SuiteToOSSL.put("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA","EXP1024-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA","EXP1024-RC4-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA","EXP1024-DHE-DSS-DES-CBC-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA","EXP1024-DHE-DSS-RC4-SHA");
        SuiteToOSSL.put("TLS_DHE_DSS_WITH_RC4_128_SHA","DHE-DSS-RC4-SHA");
        SuiteToOSSL.put("SSL_CK_RC4_128_WITH_MD5","RC4-MD5");
        SuiteToOSSL.put("SSL_CK_RC4_128_EXPORT40_WITH_MD5","EXP-RC4-MD5");
        SuiteToOSSL.put("SSL_CK_RC2_128_CBC_WITH_MD5","RC2-MD5");
        SuiteToOSSL.put("SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5","EXP-RC2-MD5");
        SuiteToOSSL.put("SSL_CK_IDEA_128_CBC_WITH_MD5","IDEA-CBC-MD5");
        SuiteToOSSL.put("SSL_CK_DES_64_CBC_WITH_MD5","DES-CBC-MD5");
        SuiteToOSSL.put("SSL_CK_DES_192_EDE3_CBC_WITH_MD5","DES-CBC3-MD5");

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", name = "ECDHE-ECDSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", name = "ECDHE-ECDSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", name = "ECDHE-ECDSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", name = "ECDHE-ECDSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", name = "ECDHE-ECDSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", name = "ECDHE-ECDSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", name = "ECDHE-RSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", name = "ECDHE-RSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", name = "ECDHE-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_RSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", name = "ECDHE-RSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", name = "ECDHE-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", name = "ECDHE-RSA-AES256-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", name = "ECDH-ECDSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", name = "ECDH-ECDSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", name = "ECDH-ECDSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", name = "ECDH-ECDSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",  name = "ECDH-ECDSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  name = "ECDH-ECDSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aECDSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", name = "ECDH-RSA-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", name = "ECDH-RSA-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", name = "ECDH-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", name = "ECDH-RSA-AES128-SHA256");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", name = "ECDH-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", name = "ECDH-RSA-AES256-SHA384");
	    CipherNames.put(name, new Def(name,
            SSL_kECDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-ECDSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH-ECDSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "ECDH-RSA-DES-CBC3-SHA");
        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE-ECDSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE-RSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDH-ECDSA-RC4-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_RC4_128_SHA", "ECDH-RSA-RC4-SHA");

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_AES_128_CBC_SHA", name = "AECDH-AES128-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", name = "AECDH-AES256-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_AES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", name = "AECDH-DES-CBC3-SHA");
	    CipherNames.put(name, new Def(name,
            SSL_kECDHE|SSL_aNULL|SSL_3DES|SSL_SHA|SSL_TLSV1,
            SSL_NOT_EXP|SSL_HIGH, 168, 168, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDH_anon_WITH_RC4_128_SHA", name = "AECDH-RC4-SHA");
        CipherNames.put(name, new Def(name,
                SSL_kECDHE|SSL_aNULL|SSL_RC4|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 128, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", name = "DHE-RSA-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", name = "DHE-RSA-AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", name = "DHE-RSA-AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", name = "DHE-RSA-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", name = "DHE-DSS-AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", name = "DHE-DSS-AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", name = "DHE-DSS-AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", name = "DHE-DSS-AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_kEDH|SSL_aDSS|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_GCM_SHA256", name = "AES128-GCM-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_128_CBC_SHA256", name = "AES128-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 128, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_CBC_SHA256", name = "AES256-SHA256");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 256, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_RSA_WITH_AES_256_GCM_SHA384", name = "AES256-GCM-SHA384");
        CipherNames.put(name, new Def(name,
                SSL_aRSA|SSL_AES|SSL_SHA|SSL_TLSV1,
                SSL_NOT_EXP, 256, 384, SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS
        ));

        SuiteToOSSL.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE-ECDSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDHE_RSA_WITH_NULL_SHA", "ECDHE-RSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_ECDSA_WITH_NULL_SHA", "ECDH-ECDSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_RSA_WITH_NULL_SHA", "ECDH-RSA-NULL-SHA");
        SuiteToOSSL.put("TLS_ECDH_anon_WITH_NULL_SHA", "AECDH-NULL-SHA");

        /* For IBM JRE: suite names start with "SSL_". On Oracle JRE, the suite names start with "TLS_" */
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_CBC_SHA",        "ADH-AES128-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_CBC_SHA256",     "ADH-AES128-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_128_GCM_SHA256",     "ADH-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_CBC_SHA",        "ADH-AES256-SHA");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_CBC_SHA256",     "ADH-AES256-SHA256");
        SuiteToOSSL.put("SSL_DH_anon_WITH_AES_256_GCM_SHA384",     "ADH-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_CBC_SHA",        "DHE-DSS-AES128-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_CBC_SHA256",     "DHE-DSS-AES128-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_128_GCM_SHA256",     "DHE-DSS-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_CBC_SHA",        "DHE-DSS-AES256-SHA");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_CBC_SHA256",     "DHE-DSS-AES256-SHA256");
        SuiteToOSSL.put("SSL_DHE_DSS_WITH_AES_256_GCM_SHA384",     "DHE-DSS-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_CBC_SHA",        "DHE-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_CBC_SHA256",     "DHE-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_128_GCM_SHA256",     "DHE-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_CBC_SHA",        "DHE-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_CBC_SHA256",     "DHE-RSA-AES256-SHA256");
        SuiteToOSSL.put("SSL_DHE_RSA_WITH_AES_256_GCM_SHA384",     "DHE-RSA-AES256-GCM-SHA384");

        SuiteToOSSL.put("SSL_ECDH_anon_WITH_AES_128_CBC_SHA",      "AECDH-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_anon_WITH_AES_256_CBC_SHA",      "AECDH-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_anon_WITH_NULL_SHA",             "AECDH-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_CBC_SHA",     "ECDH-ECDSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",  "ECDH-ECDSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",  "ECDH-ECDSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_CBC_SHA",     "ECDH-ECDSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",  "ECDH-ECDSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",  "ECDH-ECDSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDH_ECDSA_WITH_NULL_SHA",            "ECDH-ECDSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_CBC_SHA",       "ECDH-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_CBC_SHA256",    "ECDH-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_128_GCM_SHA256",    "ECDH-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_CBC_SHA",       "ECDH-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_CBC_SHA384",    "ECDH-RSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_AES_256_GCM_SHA384",    "ECDH-RSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDH_RSA_WITH_NULL_SHA",              "ECDH-RSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",    "ECDHE-ECDSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE-ECDSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",    "ECDHE-ECDSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE-ECDSA-AES256-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_ECDSA_WITH_NULL_SHA",           "ECDHE-ECDSA-NULL-SHA");

        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA",      "ECDHE-RSA-AES128-SHA");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA256",   "ECDHE-RSA-AES128-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA",      "ECDHE-RSA-AES256-SHA");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_CBC_SHA384",   "ECDHE-RSA-AES128-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256",   "ECDHE-RSA-AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   "ECDHE-RSA-AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_ECDHE_RSA_WITH_NULL_SHA",             "ECDHE-RSA-NULL-SHA");

        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_CBC_SHA",            "AES128-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_CBC_SHA256",         "AES128-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_128_GCM_SHA256",         "AES128-GCM-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_CBC_SHA",            "AES256-SHA");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_CBC_SHA256",         "AES256-SHA256");
        SuiteToOSSL.put("SSL_RSA_WITH_AES_256_GCM_SHA384",         "AES256-GCM-SHA384");
        SuiteToOSSL.put("SSL_RSA_WITH_NULL_SHA256",                "NULL-SHA256");

        // left overs supported by Java 7's SSLv3 / TLS v1.2 :

        //    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        //    TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
        //    TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
        //    TLS_KRB5_WITH_RC4_128_SHA,
        //    TLS_KRB5_WITH_RC4_128_MD5,
        //    TLS_KRB5_WITH_DES_CBC_SHA,
        //    TLS_KRB5_WITH_DES_CBC_MD5,
        //    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
        //    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
        //    TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
        //    TLS_KRB5_EXPORT_WITH_RC4_40_MD5

        for ( Def def : Ciphers ) CipherNames.put(def.name, def);

	}

}// CipherStrings
