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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public class Main {

    private static final String hostnameRegex = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$"; //Credit: http://www.mkyong.com/regular-expressions/domain-name-regular-expression-example/
    private static final Pattern hostnamePattern = Pattern.compile(hostnameRegex);
    private static final DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
    public static final Set<String> arrWildcardExceptions = new HashSet<>();
    public static final Set<String> arrWildcardBlock = new HashSet<>();
    public static int RAW_COUNT = 0;
    public static final HashMap<String, HashSet<String>> listMap = new HashMap<>();
    public static boolean CACHE_ONLY = false; //For testing use

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
            final Set<String> arrAllowlistWWW = new HashSet<>();
            for(String domain : arrAllowlist) {
                if (!domain.startsWith("www.")) {
                    arrAllowlistWWW.add("www." + domain);
                }
            }
            arrAllowlist.addAll(arrAllowlistWWW);
            System.out.println("Loaded " + arrAllowlist.size() + " excluded domains");
        } else {
            System.out.println("Allowlist file doesn't exist!");
            System.exit(1);
        }
        File allowListWildcards = new File("allowlist-wildcards.txt");
        if (allowListWildcards.exists()) {
            arrWildcardExceptions.addAll(readFileIntoArray(allowListWildcards));
        }
        File blockListWildcards = new File("blocklist-wildcards.txt");
        if (blockListWildcards.exists()) {
            arrWildcardBlock.addAll(readFileIntoArray(blockListWildcards));
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
                //Download the file
                String encodedName = byteArrayToHexString(MessageDigest.getInstance("MD5").digest(url.getBytes(StandardCharsets.UTF_8)));
                System.out.println("Processing " + url + " / " + encodedName);
                File out = new File(cacheDir, encodedName + identifyFileType(url));
                downloadFile(url, out.toPath());
                //Parse the file
                HashSet<String> listResult = new HashSet<>();
                listResult.addAll(readHostsFileIntoArray(out));
                listMap.put(url, listResult);
                arrDomains.addAll(listResult);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        //Remove excluded entries
        int preSize = arrDomains.size();
        ArrayList<String> arrDomainsRemoved = new ArrayList<>();
        for (String domainToRemove : arrAllowlist) {
            if (arrDomains.remove(domainToRemove)) {
                arrDomainsRemoved.add(domainToRemove);
            }
        }
        Collections.sort(arrDomainsRemoved);
        System.out.println("Removed " + (preSize - arrDomains.size()) + " excluded entries");

        //Sorting
        ArrayList<String> arrDomainsSorted = new ArrayList<>(arrDomains);
        Collections.sort(arrDomainsSorted);
        ArrayList<String> arrDomainsWildcardsSorted = new ArrayList<>(wildcardOptimizer(arrDomains));
        Collections.sort(arrDomainsWildcardsSorted);
        System.out.println("Processed " + arrDomains.size() + " domains");

        //Get the output file
        writeOut(new File(args[2]), arrBlocklists, arrDomainsSorted, 0, arrDomainsSorted.size());
        writeOut(new File(args[2] + "-domains"), arrBlocklists, arrDomainsSorted, 1, arrDomainsSorted.size());
        writeOut(new File(args[2] + "-wildcards"), arrBlocklists, arrDomainsWildcardsSorted, 0, arrDomainsSorted.size());
        writeOut(new File(args[2] + "-domains-wildcards"), arrBlocklists, arrDomainsWildcardsSorted, 1, arrDomainsSorted.size());
        writeOut(new File(args[2] + "-dnsmasq"), arrBlocklists, arrDomainsWildcardsSorted, 2, arrDomainsSorted.size());
        writeArrayToFile(new File(args[2] + "-removed"), arrDomainsRemoved);
        generateCrossCheck(new File(args[2] + "-xcheck"));
    }

    public static void generateCrossCheck(File out) {
        System.out.println("Generating crosscheck results");
        ArrayList<String> xcheckResult = new ArrayList<>();
        for (Map.Entry<String, HashSet<String>> entry : listMap.entrySet()) {
            xcheckResult.add(entry.getKey());
            xcheckResult.add("----------------------------------------------------------------");
            boolean matchFound = false;
            for (Map.Entry<String, HashSet<String>> recurseEntry : listMap.entrySet()) {
                if (!recurseEntry.getKey().equals(entry.getKey())) {
                    int count = 0;
                    for (String domain : entry.getValue()) {
                        if (recurseEntry.getValue().contains(domain)) {
                            count++;
                        }
                    }
                    int percent = (int) ((100D / recurseEntry.getValue().size()) * count);
                    if (count != 0 && percent > 0) {
                        xcheckResult.add(count + "\t~" + percent + "%" + "\t\t" + recurseEntry.getKey());
                        matchFound = true;
                    }
                }
            }
            if (!matchFound) {
                xcheckResult.add("No significant number of entries found in any other lists.");
            }
            xcheckResult.add("\n");
        }
        writeArrayToFile(out, xcheckResult);
    }

    public static void writeOut(File fileOut, ArrayList<String> arrBlocklists, ArrayList<String> arrDomains, int mode, int trueCount) {
        if (fileOut.exists()) {
            fileOut.renameTo(new File(fileOut + ".bak"));
        }
        //Write the file
        try {
            PrintWriter writer = new PrintWriter(fileOut, "UTF-8");
            writer.println("#");
            writer.println("#Created using Simple Hosts Merger");
            writer.println("#Last Updated: " + dateFormat.format(Calendar.getInstance().getTime()));
            writer.println("#Number of Entries:");
            writer.println("#\tInput Count: " + RAW_COUNT);
            writer.println("#\tResult Count: " + trueCount);
            if (trueCount != arrDomains.size()) {
                writer.println("#\tAfter Wildcards: " + arrDomains.size());
            }
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
                switch (mode) {
                    case 0: //hosts
                        writer.println("0.0.0.0 " + line);
                        break;
                    case 1: //domains only
                        writer.println(line);
                        break;
                    case 2: //dnsmasq
                        if (!line.startsWith("*.")) {
                            writer.println("address=/" + line + "/#");
                        }
                        break;
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
            if (out.toFile().exists() && CACHE_ONLY) {
                System.out.println("\tUsing cached version");
            } else {
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
            }
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

    public static void writeArrayToFile(File fileOut, ArrayList<String> contents) {
        if (fileOut.exists()) {
            fileOut.renameTo(new File(fileOut + ".bak"));
        }
        //Write the file
        try {
            PrintWriter writer = new PrintWriter(fileOut, "UTF-8");
            for (String line : contents) {
                writer.println(line);
            }
            writer.close();
            System.out.println("Wrote out to " + fileOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
        contents.clear();
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
                RAW_COUNT++;
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
                    String matchedDomain = matcher.group();
/*                    if(matchedDomain.startsWith("www.")) {
                        domains.add(matchedDomain.substring(4));
                    }*/
                    domains.add(matchedDomain);
                } else if (aSpaceSplit.contains("xn--") && !aSpaceSplit.contains("/host/")) {//Ugly
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

    private static final ConcurrentLinkedQueue<Future<?>> futures = new ConcurrentLinkedQueue<>();

    public static Set<String> wildcardOptimizer(Set<String> domains) {
        Set<String> wildcards = new HashSet<>();
        ConcurrentSkipListSet<String> domainsNew = new ConcurrentSkipListSet<>();
        ConcurrentHashMap<String, AtomicInteger> occurrenceMap = new ConcurrentHashMap<>();
        ThreadPoolExecutor threadPoolExecutorWork = new ThreadPoolExecutor(8, 8, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>(4), new ThreadPoolExecutor.CallerRunsPolicy());

        // Count the occurrence of each entry with one level removed
        for (String domain : domains) {
            futures.add(threadPoolExecutorWork.submit(() -> {
                String[] domainSplit = domain.split("\\.");
                for (int shift = 1; shift < 20; shift++) {
                    if (domainSplit.length > shift + 1) {
                        String shifted = jankSplit(domain, shift);
                        if (shifted.length() > 0) {
                            occurrenceMap.putIfAbsent(shifted, new AtomicInteger());
                            occurrenceMap.get(shifted).getAndIncrement();
                        }
                    }
                }
            }));
        }
        waitForThreadsComplete();

        // Mark entries with count past X as a wildcard candidate
        for (Map.Entry<String, AtomicInteger> domain : occurrenceMap.entrySet()) {
            if (domain.getValue().get() >= 50) {
                wildcards.add(domain.getKey());
            }
        }
        wildcards.addAll(arrWildcardBlock);

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
        wildcards = null; //set null to prevent accidental use

        // Exclude all domains that would be matched by the wildcard and include the rest
        domainsNew.addAll(domains);
        for (String domain : domains) {
            futures.add(threadPoolExecutorWork.submit(() -> {
                for (String wildcard : wildcardsNew) {
                    if (domain.endsWith("." + wildcard)) {
                        domainsNew.remove(domain);
                    }
                }
            }));
        }
        waitForThreadsComplete();

        //Add the wildcards
        for (String wildcard : wildcardsNew) {
            domainsNew.add("*." + wildcard);
            domainsNew.add(wildcard);
        }

        threadPoolExecutorWork.shutdown();
        System.out.println("Replaced " + (domains.size() - (domainsNew.size() - wildcardsNew.size())) + " domains with " + wildcardsNew.size() + " wildcards");

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

    private static void waitForThreadsComplete() {
        try {
            for (Future<?> future : futures) {
                future.get();
                futures.remove(future);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        futures.clear();
    }

}
