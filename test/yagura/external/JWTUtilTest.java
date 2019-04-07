package yagura.external;

import yagura.model.JWTObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import yagura.model.JWTToken;

/**
 *
 * @author isayan
 */
public class JWTUtilTest {
    
    public JWTUtilTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of isJWTFormat method, of class JWTUtil.
     */
    @Test
    public void testIsJWTFormat() {
        System.out.println("isJWTFormat");
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            boolean expResult = true;
            //value = value.replace("-_", "+/");
            boolean result = JWTObject.isJWTFormat(value);
            assertEquals(expResult, result);        
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            //value = value.replace("-_", "+/");
            boolean expResult = false;
            boolean result = JWTObject.isJWTFormat(value);
            assertEquals(expResult, result);        
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiPj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8iLCJzdWIiOiLjg4bjgrnjg4gifQ.X3cI5c0oMucE4ysk-hfpqn6OSjmS-xXMVhhR_FpHJMQ";
            boolean expResult = true;
            boolean result = JWTObject.isJWTFormat(value);
            assertEquals(expResult, result);                    
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U";
            boolean expResult = true;
            boolean result = JWTObject.isJWTFormat(value);
            assertEquals(expResult, result);                    
        }
        {
            String value = "xeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            //value = value.replace("-_", "+/");
            boolean expResult = false;
            boolean result = JWTObject.isJWTFormat(value);
            assertEquals(expResult, result);        
        }
    }

    
    /**
     * Test of parseJWTToken method, of class JWTUtil.
     */
    @Test
    public void testParseJWTToken() {
        System.out.println("parseJWTToken");
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            JWTToken expResult = null;
            //value = value.replace("-_", "+/");
            JWTToken result = JWTObject.parseJWTToken(value, true);
            assertNotEquals(expResult, result);        
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            //value = value.replace("-_", "+/");
            JWTToken expResult = null;
            JWTToken result = JWTObject.parseJWTToken(value, true);
            assertEquals(expResult, result);        
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtYWluIjoiPj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj4-Pj8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8_Pz8iLCJzdWIiOiLjg4bjgrnjg4gifQ.X3cI5c0oMucE4ysk-hfpqn6OSjmS-xXMVhhR_FpHJMQ";
            JWTToken expResult = null;
            JWTToken result = JWTObject.parseJWTToken(value, true);
            assertNotEquals(expResult, result);                    
        }
        {
            String value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U";
            JWTToken expResult = null;
            JWTToken result = JWTObject.parseJWTToken(value, true);
            assertNotEquals(expResult, result);                    
        }
        {
            String value = "xeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            //value = value.replace("-_", "+/");
            JWTToken expResult = null;
            JWTToken result = JWTObject.parseJWTToken(value, false);
            assertEquals(expResult, result);        
        }
    }
    
    /**
     * Test of ContainsJWTFormat method, of class JWTUtil.
     */
    @Test
    public void testContainsJWTFormat() {
        System.out.println("containsJWTFormat");
        String value = "Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiLjgYLjgYTjgYbjgYjjgYoifQ.I6fGHWldnjdhfOjxcs9Wtzm41dIjBiAHYl3ZAcKl4Ks";   
        boolean expResult = true;
        boolean result = JWTObject.containsJWTFormat(value);
        assertEquals(expResult, result);        
    }
    
    /**
     * Test of testParseJWTObject method, of class JWTUtil.
     */
    @Test
    public void testParseJWTObject() {
        System.out.println("parseJWTObject");
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            String expResult2 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
            String expResult3 = "5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            boolean expResult = true;
            JWTToken result = JWTToken.parseJWTToken(test, true);
            assertEquals(expResult1, result.getHeader());        
            assertEquals(expResult2, result.getPayload());        
            assertEquals(expResult3, result.getSignature());        
        }
    }

    /**
     * Test of testParseJWTObject method, of class JWTUtil.
     */
    @Test
    public void testParseJWTObject_json() {
        System.out.println("parseJWTObject");
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA";
            String expResult1 = "{\n    \"alg\":\"HS256\",\n    \"typ\":\"JWT\"\n}";
            String expResult2 = "{\n    \"sub\":\"1234567890\",\n    \"name\":\"John Doe\",\n    \"iat\":1516239022\n}";
            JWTToken token = JWTToken.parseJWTToken(test, true);
            JWTObject result = new JWTObject(token);
            assertEquals(expResult1, result.getHeaderJSON(true));        
            assertEquals(expResult2, result.getPayloadJSON(true));        
        }
        {
            String test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiLjgYLjgYTjgYbjgYjjgYoifQ.I6fGHWldnjdhfOjxcs9Wtzm41dIjBiAHYl3ZAcKl4Ks";
            String expResult1 = "{\n    \"alg\":\"HS256\",\n    \"typ\":\"JWT\"\n}";
            String expResult2 = "{\n    \"sub\":\"あいうえお\"\n}";
            JWTToken token = JWTToken.parseJWTToken(test, true);
            JWTObject result = new JWTObject(token);
            assertEquals(expResult1, result.getHeaderJSON(true));        
            assertEquals(expResult2, result.getPayloadJSON(true));        
        }
    }

}
