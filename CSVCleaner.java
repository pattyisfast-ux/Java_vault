import java.io.*;

public class CSVCleaner {
    public static void main(String[] args) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("input.csv"));
        PrintWriter pw = new PrintWriter(new FileWriter("cleaned.csv"));
        String line;
        while ((line = br.readLine()) != null) {
            pw.println(line.trim()); // remove extra spaces
        }
        br.close();
        pw.close();
        System.out.println("CSV cleaned and saved!");
    }
}