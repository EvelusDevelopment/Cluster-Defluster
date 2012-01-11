package org.evelus;

import java.io.ByteArrayInputStream;
import org.evelus.util.AESUtility;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.JarURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.objectweb.asm.ClassReader;

/**
 * Main.java
 * @version 1.0.0
 * @author Evelus Development (SiniSoul)
 */
public class Main {
    
    /**
     * The regular expression pattern used for finding the name of the jar file
     * in which we will be downloading from the Runescape website.
     */
    private static Pattern ARCHIVEPATTERN = Pattern.compile("archive=(.*)  ");
    
    /**
     * The regular expression pattern used for finding the encryption key
     * used in the decryption of the inner.pack.gz.
     */
    private static Pattern KEYPATTERN = Pattern.compile("0\" value=\"(\\S{22})\"");
    
    /**
     * The regular expression pattern used for finding the initialization vector
     * used in the decryption of the inner.pack.gz.
     */
    private static Pattern IVPATTERN = Pattern.compile("-1\" value=\"(\\S{22})\"");
    
    /**
     * The map which contains the source of each of the compiled class files for
     * evaluation and comparison. 
     */
    private static Map<String, byte[]> CLASSES = new HashMap<String, byte[]>();
    
    /**
     * The main entry point for this program.
     * @param args The command line arguments. 
     */
    public static void main(String[] args) throws Exception {
        System.out.println("Cluster Defluster written by SiniSoul");
        String source = "http://world1.runescape.com/g=runescape/";
        String page = getWebsitePage(source + ",j0");
        Matcher archiveMatcher = ARCHIVEPATTERN.matcher(page);
        if(archiveMatcher.find()) {
            System.out.println("\t-Downloading the loader jar file...");
            JarURLConnection connection = (JarURLConnection) new URL("jar:" + source+ archiveMatcher.group(1) + "!/").openConnection();
            JarFile loaderJarFile = connection.getJarFile();
            System.out.println("\t-Deciphering the inner.pack.gz...");
            Matcher vectorMatcher = IVPATTERN.matcher(page);
            Matcher keyMatcher = KEYPATTERN.matcher(page);
            byte[] src = null;
            if(vectorMatcher.find() && keyMatcher.find())                     
                src = AESUtility.decipherPack(loaderJarFile.getInputStream(loaderJarFile.getEntry("inner.pack.gz")), 
                                                           keyMatcher.group(1), vectorMatcher.group(1));
            System.out.println("\t-Mapping the class file data...");
            byte[] buffer = new byte[5242880]; 
            JarInputStream gameJarFile = new JarInputStream(new ByteArrayInputStream(src));
            JarEntry entry = null;       
            while((entry = gameJarFile.getNextJarEntry()) != null) {
                if(!entry.getName().endsWith(".class"))
                    continue;
                String name = entry.getName().replaceAll("/", ".").replaceAll(".class", "");
                int off = 0, read = 0;
                while(read != -1) {
                    if((read = gameJarFile.read(buffer, off, buffer.length - off)) < 0)
                        break;
                    off += read;
                }
                byte[] array = new byte[off];
                System.arraycopy(buffer, 0, array, 0, off);
                CLASSES.put(name, array);
            }
            System.out.println("\t-Analyzing the class files...");
            for(String key : CLASSES.keySet()) {
                ClassReader reader = new ClassReader(CLASSES.get(key));
            }
        }
        System.out.println("Finished");
    }
    
    /**
     * 
     * @param source
     * @return
     * @throws MalformedURLException
     * @throws IOException 
     */
    private static String getWebsitePage(String source) throws MalformedURLException, IOException {
        URLConnection connection = new URL(source).openConnection();
        byte[] array = new byte[connection.getContentLength()];
        new DataInputStream(connection.getInputStream()).readFully(array);
        return new String(array);
    }
}
