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
import java.nio.charset.StandardCharsets;
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
    private static final Pattern hostnamePattern = Pattern.compile(hostnameRegex);
    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
    public static final Set<String> arrWildcardExceptions = new HashSet<>();

    public static void main(String[] args) {
        System.out.println("Simple Hosts Merger");
        System.out.println("Copyright 2015-2021 Divested Computing Group");
        System.out.println("License: GPLv3\n");
        if (args.length != 4) {
            System.out.println("Four arguments required: exclusion file, blocklists config (format: link,license;\\n), output file, cache dir");
            System.exit(1);
        }

        //Get the allowlists
        final Set<String> arrAllowlist = new HashSet<>();
        File allowlist = new File(args[0]);
        if (allowlist.exists()) {
            arrAllowlist.addAll(readFileIntoArray(allowlist));
            System.out.println("Loaded " + arrAllowlist.size() + " excluded domains");
        } else {
            System.out.println("Allowlist file doesn't exist!");
            System.exit(1);
        }
        File allowListWildcards = new File("allowlist-wildcards.txt");
        if (allowListWildcards.exists()) {
            arrWildcardExceptions.addAll(readFileIntoArray(allowListWildcards));
        }
        File publicSuffixList = new File("public_suffix_list.dat");
        if (publicSuffixList.exists()) {
            arrWildcardExceptions.addAll(readFileIntoArray(publicSuffixList));
        }
        arrWildcardExceptions.addAll(arrAllowlist);
        System.out.println("Loaded " + arrWildcardExceptions.size() + " excluded wildcards");

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

        //Get the cache dir
        File cacheDir = new File(args[3]);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }

        //Process the blocklists
        Set<String> arrDomains = new HashSet<>();
        for (String list : arrBlocklists) {
            String url = list.split(",")[0];
            try {
                System.out.println("Processing " + url);
                //Download the file
                String encodedName = byteArrayToHexString(MessageDigest.getInstance("MD5").digest(url.getBytes(StandardCharsets.UTF_8)));
                File out = new File(cacheDir, encodedName + identifyFileType(url));
                downloadFile(url, out.toPath());
                //Parse the file
                arrDomains.addAll(readHostsFileIntoArray(out));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //Remove excluded entries
        int preSize = arrDomains.size();
        arrDomains.removeAll(arrAllowlist);
        System.out.println("Removed " + (preSize - arrDomains.size()) + " excluded entries");

        //Sorting
        ArrayList<String> arrDomainsSorted = new ArrayList<>(arrDomains);
        Collections.sort(arrDomainsSorted);
        ArrayList<String> arrDomainsWildcardsSorted = new ArrayList<>(wildcardOptimizer(arrDomains));
        Collections.sort(arrDomainsWildcardsSorted);
        System.out.println("Processed " + arrDomains.size() + " domains");

        //Get the output file
        writeOut(new File(args[2]), arrBlocklists, arrDomainsSorted, false);
        writeOut(new File(args[2] + "-domains"), arrBlocklists, arrDomainsSorted, true);
        writeOut(new File(args[2] + "-wildcards"), arrBlocklists, arrDomainsWildcardsSorted, false);
        writeOut(new File(args[2] + "-domains-wildcards"), arrBlocklists, arrDomainsWildcardsSorted, true);

    }

    public static void writeOut(File fileOut, ArrayList<String> arrBlocklists, ArrayList<String> arrDomains, boolean domainsOnly) {
        if (fileOut.exists()) {
            fileOut.renameTo(new File(fileOut + ".bak"));
        }
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
            for (String line : arrDomains) {
                if (domainsOnly) {
                    writer.println(line);
                } else {
                    writer.println("0.0.0.0 " + line);
                }
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
            connection.addRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0");
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

    //Credit (CC BY-SA 2.5): https://stackoverflow.com/a/4895572
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

    public static ArrayList<String> readFileIntoArray(File in) {
        ArrayList<String> out = new ArrayList<>();
        try {
            Scanner scanner = new Scanner(in);
            while (scanner.hasNext()) {
                String line = scanner.nextLine();
                if (!line.startsWith("#") && !line.startsWith("//")) {
                    out.add(line);
                }
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out;
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
            while (fileIn.hasNext()) {
                out.addAll(getDomainsFromString(fileIn.nextLine()));
            }
            System.out.println("\tAdded " + out.size() + " entries");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out;
    }

    public static Set<String> getDomainsFromString(String input) {
        Set<String> domains = new HashSet<>();

        String line = input.toLowerCase();
        if (!shouldConsiderString(line)) {
            return domains;
        }

        String[] blankSplit = line
                .replaceAll("[\\s,;]", "~")
                .split("~");

        Matcher matcher;
        for (String aSpaceSplit : blankSplit) {
            if (shouldConsiderString(line)) {
                aSpaceSplit = aSpaceSplit
                        .replaceAll("https://", "")
                        .replaceAll("http://", "")
                        .replaceAll("ftp://", "");
                //.replaceAll("/.*", "");
                matcher = hostnamePattern.matcher(aSpaceSplit);//Apply the pattern to the string
                if (matcher.find()) {//Check if the string meets our requirements
                    domains.add(matcher.group());
                } else if (aSpaceSplit.contains("xn--")) {//Ugly
                    domains.add(aSpaceSplit);
                }
            }
        }

        return domains;
    }

    public static boolean shouldConsiderString(String line) {
        return !line.trim().equals("")
                && !line.startsWith("#")
                && !line.startsWith(";")
                && !line.startsWith("!")
                && !line.startsWith("//")
                && !line.startsWith("$")
                && !line.startsWith("@");
    }

    public static Set<String> wildcardOptimizer(Set<String> domains) {
        Set<String> wildcards = new HashSet<>();
        Set<String> domainsNew = new HashSet<>();
        Map<String, Integer> occurrenceMap = new HashMap<>();

        // Count the occurrence of each entry with one level removed
        for (int shift = 1; shift < 20; shift++) {
            for (String domain : domains) {
                if (domain.split("\\.").length > shift + 1) {
                    String shifted = jankSplit(domain, shift);
                    if (shifted.length() > 0) {
                        occurrenceMap.merge(shifted, 1, Integer::sum);
                    }
                }
            }
        }

        // Mark entries with count past X as a wildcard candidate
        for (Map.Entry<String, Integer> domain : occurrenceMap.entrySet()) {
            if (domain.getValue() >= 50) {
                wildcards.add(domain.getKey());
            }
        }

        //Exclude removal of certain domains
        for (String exception : arrWildcardExceptions) {
            wildcards.remove(exception);
        }

        //Remove redundant wildcards
        Set<String> wildcardsNew = new HashSet<>();
        wildcardsNew.addAll(wildcards);
        for (String wildcard : wildcards) {
            for (String wildcardCheck : wildcards) {
                if (!wildcard.equals(wildcardCheck) && wildcardCheck.endsWith("." + wildcard)) {
                    wildcardsNew.remove(wildcardCheck);
                }
            }
        }
        wildcards = wildcardsNew;

        // Exclude all domains that would be matched by the wildcard and include the rest
        domainsNew.addAll(domains);
        for (String domain : domains) {
            for (String wildcard : wildcards) {
                if (domain.endsWith("." + wildcard)) {
                    domainsNew.remove(domain);
                }
            }
        }

        //Add the wildcards
        for (String wildcard : wildcards) {
            domainsNew.add("*." + wildcard);
            domainsNew.add(wildcard);
        }

        System.out.println("Replaced " + (domains.size() - (domainsNew.size() - wildcards.size())) + " domains with " + wildcards.size() + " wildcards");

        return domainsNew;
    }

    public static String jankSplit(String input, int afterOccurrence) {
        StringBuilder result = new StringBuilder();
        String[] split = input.split("\\.");
        for (int count = 0; count < split.length; count++) {
            if (count >= afterOccurrence) {
                result.append(split[count]);
                if (count != (split.length - 1)) {
                    result.append(".");
                }
            }
        }
        return result.toString();
    }

}
