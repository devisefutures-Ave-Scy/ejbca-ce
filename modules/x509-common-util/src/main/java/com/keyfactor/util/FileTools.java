/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.apache.log4j.Logger
 */
package com.keyfactor.util;

import com.keyfactor.util.Base64;
import com.keyfactor.util.StreamSizeLimitExceededException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.Collator;
import java.util.Arrays;
import java.util.Comparator;
import org.apache.log4j.Logger;

public abstract class FileTools {
    private static final Logger log = Logger.getLogger(FileTools.class);
    private static final int ZIP_HEADER_SIZE = 4;
    private static final byte[] ZIP_LOCAL_HEADER = new byte[]{80, 75, 3, 4};
    private static final byte[] ZIP_END_OF_CENTRAL_HEADER = new byte[]{80, 75, 5, 6};

    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey) throws IOException {
        ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        return FileTools.getBytesFromPEM(instream, beginKey, endKey);
    }

    public static byte[] getBytesFromPEM(InputStream instream, String beginKey, String endKey) throws IOException {
        byte[] bytes;
        String temp;
        if (log.isTraceEnabled()) {
            log.trace((Object)">getBytesFromPEM");
        }
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        PrintStream opstr = new PrintStream(ostr);
        while ((temp = bufRdr.readLine()) != null && !temp.equals(beginKey)) {
        }
        if (temp == null) {
            throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
        }
        while ((temp = bufRdr.readLine()) != null && !temp.equals(endKey)) {
            if (temp.trim().length() <= 0) continue;
            opstr.print(temp);
        }
        if (temp == null) {
            throw new IOException("Error in input buffer, missing " + endKey + " boundary");
        }
        opstr.close();
        try {
            bytes = Base64.decode(ostr.toByteArray());
        }
        catch (Exception e) {
            throw new IOException("Malformed PEM encoding or PEM of unknown type: " + e.getMessage());
        }
        if (log.isTraceEnabled()) {
            log.trace((Object)"<getBytesFromPEM");
        }
        return bytes;
    }

    public static byte[] readFiletoBuffer(String file) throws FileNotFoundException {
        FileInputStream in = new FileInputStream(file);
        return FileTools.readInputStreamtoBuffer(in);
    }

    public static byte[] readInputStreamtoBuffer(InputStream in) {
        byte[] byArray;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            int len = 0;
            byte[] buf = new byte[1024];
            while ((len = in.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            in.close();
            byArray = os.toByteArray();
        }
        catch (Throwable throwable) {
            try {
                try {
                    os.close();
                }
                catch (Throwable throwable2) {
                    throwable.addSuppressed(throwable2);
                }
                throw throwable;
            }
            catch (IOException e) {
                throw new RuntimeException("Caught IOException for unknown reason", e);
            }
        }
        os.close();
        return byArray;
    }

    public static void sortByName(File[] files) {
        if (files == null) {
            return;
        }
        Arrays.sort(files, new FileComp());
    }

    public static File createTempDirectory() throws IOException {
        return FileTools.createTempDirectory(null);
    }

    public static File createTempDirectory(File location) throws IOException {
        File temp = File.createTempFile("tmp", Long.toString(System.nanoTime()), location);
        if (!temp.delete()) {
            throw new IOException("Could not delete temp file: " + temp.getAbsolutePath());
        }
        if (!temp.mkdir()) {
            throw new IOException("Could not create temp directory: " + temp.getAbsolutePath());
        }
        return temp;
    }

    public static void delete(File file) {
        if (file.isDirectory()) {
            for (File subFile : file.listFiles()) {
                FileTools.delete(subFile);
            }
        }
        if (!file.delete()) {
            log.error((Object)("Could not delete directory " + file.getAbsolutePath()));
        }
    }

    public static long streamCopyWithLimit(InputStream input, OutputStream output, long maxBytes) throws IOException {
        int len;
        if (maxBytes < 0L || maxBytes == 0L && input.read() != -1) {
            throw new StreamSizeLimitExceededException("Size limit was reached");
        }
        if (maxBytes == 0L) {
            return 0L;
        }
        byte[] buff = new byte[16384];
        long bytesCopied = 0L;
        while ((len = input.read(buff)) > 0) {
            if ((bytesCopied += (long)len) > maxBytes) {
                throw new StreamSizeLimitExceededException("Size limit was reached");
            }
            output.write(buff, 0, len);
        }
        return bytesCopied;
    }

    public static byte[] readStreamToByteArray(InputStream inputStream, int expectedSize, int maxSize) throws StreamSizeLimitExceededException, IOException {
        int maxSizeBytes;
        int expectedSizeBytes;
        int maxBytes;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(expectedSize != -1 ? expectedSize : 1024);
        long bytesCopied = FileTools.streamCopyWithLimit(inputStream, baos, maxBytes = Math.min(expectedSizeBytes = expectedSize != -1 ? expectedSize : Integer.MAX_VALUE, maxSizeBytes = maxSize != -1 ? maxSize : Integer.MAX_VALUE));
        if (bytesCopied < (long)expectedSize) {
            throw new EOFException("Less file data than expected. Was " + bytesCopied + " but expected " + expectedSize);
        }
        return baos.toByteArray();
    }

    public static boolean isZipFile(byte[] fileData) {
        byte[] header = Arrays.copyOfRange(fileData, 0, 4);
        return Arrays.equals(header, ZIP_LOCAL_HEADER) || Arrays.equals(header, ZIP_END_OF_CENTRAL_HEADER);
    }

    public static boolean isEmptyZipFile(byte[] fileData) {
        byte[] header = Arrays.copyOfRange(fileData, 0, 4);
        return Arrays.equals(header, ZIP_END_OF_CENTRAL_HEADER);
    }

    private static class FileComp
    implements Comparator<File> {
        private final Collator c = Collator.getInstance();

        private FileComp() {
        }

        @Override
        public int compare(File f1, File f2) {
            if (f1 == f2) {
                return 0;
            }
            if (f1.isDirectory() && f2.isFile()) {
                return -1;
            }
            if (f1.isFile() && f2.isDirectory()) {
                return 1;
            }
            return this.c.compare(f1.getName(), f2.getName());
        }
    }
}

