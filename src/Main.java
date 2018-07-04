/*
Copyright (c) 2015-2018 Divested Computing, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public class Main {

    private static final String hostnameRegex = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$"; //Credit: http://www.mkyong.com/regular-expressions/domain-name-regular-expression-example/
    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");

    public static void main(String[] args) {
        System.out.println("Simple Hosts Merger");
        System.out.println("Copyright 2015-2018 Divested Computing, Inc.");
        System.out.println("License: GPLv3");
        System.out.println("");
        if (args.length != 3) {
            System.out.println("Please supply the following three arguments: cache directory, output file, blocklists");
            System.exit(1);
        }

        //Get the cache dir
        File cacheDir = new File(args[0]);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }
        //Get the output file
        File fileOut = new File(args[1]);
        if (fileOut.exists()) {
            fileOut.renameTo(new File(fileOut + ".bak"));
        }
        //Process the blocklists
        String[] blocklists = args[2].split(":");
        final Set<String> arrDomains = new HashSet<>();
        for (String list : blocklists) {
            try {
                System.out.println("Processing " + list);
                //Download the file
                String encodedName = byteArrayToHexString(MessageDigest.getInstance("MD5").digest(list.getBytes("utf-8")));
                File out = new File(cacheDir, encodedName + identifyFileType(list));
                downloadFile(list, out.toPath());
                //Parse the file
                arrDomains.addAll(readHostsFileIntoArray(out));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        System.out.println("Processed " + arrDomains.size() + " domains");
        //Write the file
        try {
            PrintWriter writer = new PrintWriter(fileOut, "UTF-8");
            writer.println("#\n#Created using Trammel Lite\n#Distributed by Coverage");
            writer.println("#Last Updated: " + dateFormat.format(Calendar.getInstance().getTime()));
            writer.println("#Number of Entries: " + arrDomains.size());
            writer.println("#\n#Created from the following lists");
            writer.println("#If you would like your list removed from this list please email us at support@spotco.us");
            for (String list : blocklists) {
                writer.println("##" + list);
            }
            writer.println("#\n");

            for (String line : arrDomains) {
                writer.println(line);
            }
            writer.close();
            System.out.println("Wrote out to " + fileOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void downloadFile(String url, Path out) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(45000);
            connection.setReadTimeout(45000);
            connection.addRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:6.0) Gecko/20100101 Firefox/19.0");
            if (out.toFile().exists()) {
                connection.setIfModifiedSince(out.toFile().lastModified());
            }
            connection.connect();
            int res = connection.getResponseCode();
            if (res != 304 && (res == 200 || res == 301 || res == 302)) {
                Files.copy(connection.getInputStream(), out, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("Successfully downloaded " + url);
            }
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Credit: http://stackoverflow.com/a/4895572
    public static String byteArrayToHexString(byte[] b) {
        StringBuilder result = new StringBuilder();
        for (byte aB : b)
            result.append(Integer.toString((aB & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static String identifyFileType(String url) {
        String extension = ".txt";
        if (url.contains("zip"))
            extension = ".zip";
        else if (url.contains("gz"))
            extension = ".gz";
        else if (url.contains("7zip"))
            extension = ".7z";
        else if (url.contains("7z"))
            extension = ".7z";
        return extension;
    }

    public static ArrayList<String> readHostsFileIntoArray(File in) {
        ArrayList<String> out = new ArrayList<>();
        try {
            Scanner fileIn = null;
            if (identifyFileType(in.toString()).contains(".txt")) {//Plain text
                fileIn = new Scanner(in);
            }
            if (identifyFileType(in.toString()).contains(".gz")) {//Decompress GunZip
                fileIn = new Scanner(new GZIPInputStream(new FileInputStream(in)));
            }
            int c = 0;
            while (fileIn.hasNext()) {
                String line = fileIn.nextLine().toLowerCase();
                if (!line.startsWith("#") && !line.trim().equals("")) {//Skip if line is a comment or is blank
                    Pattern pattern = Pattern.compile(hostnameRegex);//Only look for hostnames in a string
                    line = line.replaceAll(".*\\://", "").replaceAll("/", "");
                    String[] spaceSplit = line.replaceAll("\\s", "~").split("~");
                    Matcher matcher;
                    for (String aSpaceSplit : spaceSplit) {
                        matcher = pattern.matcher(aSpaceSplit);//Apply the pattern to the string
                        if (matcher.find()) {//Check if the string meets our requirements
                            out.add("0.0.0.0 " + matcher.group());
                            c++;
                        } else if (aSpaceSplit.contains("xn--")) {
                            out.add("0.0.0.0 " + aSpaceSplit);//Sssssh, its okay
                            c++;
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out;
    }

}
