/*
Copyright (c) 2015-2019 Divested Computing Group

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
import java.io.FileNotFoundException;
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
        System.out.println("Copyright 2015-2019 Divested Computing Group");
        System.out.println("License: GPLv3\n");
        if (args.length != 4) {
            System.out.println("Four arguments required: whitelist file, blocklists config (format: link,license;\\n), output file, cache dir");
            System.exit(1);
        }
        //Get the whitelists
        final Set<String> arrWhitelist = new HashSet<>();
        File whitelist = new File(args[0]);
        if (whitelist.exists()) {
            try {
                Scanner scanner = new Scanner(whitelist);
                while (scanner.hasNext()) {
                    String line = scanner.nextLine();
                    if (!line.startsWith("#")) {
                        arrWhitelist.add(line);
                    }
                }
                scanner.close();
                System.out.println("Loaded " + arrWhitelist.size() + " whitelisted domains");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Whitelist file doesn't exist!");
            System.exit(1);
        }
        //Get the blocklists
        ArrayList<String> arrBlocklists = new ArrayList<String>();
        File blocklists = new File(args[1]);
        if (blocklists.exists()) {
            try {
                Scanner scanner = new Scanner(blocklists);
                while (scanner.hasNext()) {
                    String line = scanner.nextLine();
                    if (line.startsWith("http") && line.contains(",") && line.endsWith(";") && !line.startsWith("#")) {
                        arrBlocklists.add(line.replaceAll(";", ""));
                    }
                }
                scanner.close();
                System.out.println("Loaded " + arrBlocklists.size() + " blocklist sources");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Blocklists file doesn't exist!");
            System.exit(1);
        }
        //Get the output file
        File fileOut = new File(args[2]);
        if (fileOut.exists()) {
            fileOut.renameTo(new File(fileOut + ".bak"));
        }
        //Get the cache dir
        File cacheDir = new File(args[3]);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }

        //Process the blocklists
        final Set<String> arrDomains = new HashSet<>();
        for (String list : arrBlocklists) {
            String url = list.split(",")[0];
            try {
                System.out.println("Processing " + url);
                //Download the file
                String encodedName = byteArrayToHexString(MessageDigest.getInstance("MD5").digest(url.getBytes("utf-8")));
                File out = new File(cacheDir, encodedName + identifyFileType(url));
                downloadFile(url, out.toPath());
                //Parse the file
                arrDomains.addAll(readHostsFileIntoArray(out));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ArrayList<String> arrDomainsNew = new ArrayList<>();
        arrDomainsNew.addAll(arrDomains);
        int preSize = arrDomainsNew.size();
        arrDomainsNew.removeAll(arrWhitelist);
        Collections.sort(arrDomainsNew);
        System.out.println("Removed " + (preSize-arrDomainsNew.size()) + " whitelisted entries");
        System.out.println("Processed " + arrDomains.size() + " domains");
        //Write the file
        try {
            PrintWriter writer = new PrintWriter(fileOut, "UTF-8");
            writer.println("#");
            writer.println("#Created using Simple Hosts Merger");
            writer.println("#Last Updated: " + dateFormat.format(Calendar.getInstance().getTime()));
            writer.println("#Number of Entries: " + arrDomains.size());
            writer.println("#");
            writer.println("#Created from the following lists");
            writer.println("#All attempts have been made to ensure accuracy of the corresponding license files and their compatibility.");
            writer.println("#If you would like your list removed from this list please email us at webmaster@[THIS DOMAIN]");
            writer.println("#");
            for (String list : arrBlocklists) {
                String[] listS = list.split(",");
                writer.println("#" + listS[1] + "\t\t- " + listS[0]);
            }
            writer.println("#\n");
            for (String line : arrDomainsNew) {
                writer.println("0.0.0.0 " + line);
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
            connection.addRequestProperty("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0");
            if (out.toFile().exists()) {
                connection.setIfModifiedSince(out.toFile().lastModified());
            }
            connection.connect();
            int res = connection.getResponseCode();
            if (res != 304 && (res == 200 || res == 301 || res == 302)) {
                Files.copy(connection.getInputStream(), out, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("\tSuccessfully downloaded");
            }
            if (res == 304) {
                System.out.println("\tFile not changed");
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
        if (url.contains("=zip") || url.endsWith(".zip"))
            extension = ".zip";
        else if (url.contains("=gz") || url.endsWith(".gz"))
            extension = ".gz";
        else if (url.contains("=7zip") || url.endsWith(".7zip"))
            extension = ".7z";
        else if (url.contains("=7z") || url.endsWith(".7z"))
            extension = ".7z";
        return extension;
    }

    public static ArrayList<String> readHostsFileIntoArray(File in) {
        ArrayList<String> out = new ArrayList<>();
        try {
            Scanner fileIn = null;
            if (identifyFileType(in.toString()).equals(".txt")) {//Plain text
                fileIn = new Scanner(in);
            }
            if (identifyFileType(in.toString()).equals(".gz")) {//Decompress GunZip
                fileIn = new Scanner(new GZIPInputStream(new FileInputStream(in)));
            }
            int c = 0;
            while (fileIn.hasNext()) {
                String line = fileIn.nextLine().toLowerCase();
                if (!line.startsWith("#") && !line.startsWith(";") && !line.trim().equals("")) {//Skip if line is a comment or is blank
                    Pattern pattern = Pattern.compile(hostnameRegex);//Only look for hostnames in a string
                    //line = line.replaceAll(".*\\://", "").replaceAll("/", "");
                    String[] spaceSplit = line.replaceAll("\\s", "~").replaceAll(",", "~").split("~");
                    Matcher matcher;
                    for (String aSpaceSplit : spaceSplit) {
                        if(!aSpaceSplit.startsWith("#")
                            && !aSpaceSplit.startsWith(";")
                            && !aSpaceSplit.startsWith("//")
                            && !aSpaceSplit.startsWith("http")
                            && !aSpaceSplit.startsWith("$")
                            && !aSpaceSplit.startsWith("@")) {
                            matcher = pattern.matcher(aSpaceSplit);//Apply the pattern to the string
                            if (matcher.find()) {//Check if the string meets our requirements
                                out.add(matcher.group());
                                c++;
                            } else if (aSpaceSplit.contains("xn--")) {
                                out.add(aSpaceSplit);//Sssssh, its okay
                                c++;
                            }
                        }
                    }
                }
            }
            System.out.println("\tAdded " + c + " entries");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out;
    }

}
