package burp.scan;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.common.Common;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HadoopScan {
    static List<String> scannedUrls = new ArrayList<>();
    static URL url;
    static String baseurl;
    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    static PrintWriter stdout;
    static List<List<String>> hadoop = new ArrayList<>();
    static{
        hadoop.add(Arrays.asList("cluster"));
        hadoop.add(Arrays.asList("All Applications"));
        hadoop.add((new ArrayList<String>()));
    }

    public synchronized static List<IHttpRequestResponse> ScanMain(IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callback, IExtensionHelpers helper, PrintWriter out){
        stdout = out;
        helpers = helper;
        callbacks = callback;
        url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        baseurl = url.getProtocol() + "://" + url.getAuthority();
        List<IHttpRequestResponse> success = new ArrayList<>();
        List headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        stdout.println("开始使用漏扫插件Hadoop 进行扫描目标: "+ baseurl+url.getPath());
        List<String> scanlists = urlcheck(baseurl);
        if(!hadoop.get(2).contains(baseurl)){
            IHttpRequestResponse hadoopscan = hadoopscan(scanlists, headers, baseRequestResponse);
            success.add(hadoopscan);
        }
        stdout.println(baseurl+url.getPath() + " Hadoop插件 漏扫结束");
        return success;
    }

    public synchronized static List<String> urlcheck(String baseurl){
        List<String> ScanLists = new ArrayList<>();
        String cross = "";
        String checkurl = baseurl + "/";
        String path = url.getPath().replace("//","/");
        if (path.isEmpty()) path = "/";else path = path;
        String[] paths = path.split("/");
        if (isCheck(checkurl)){
            ScanLists.add(checkurl);
        }
        if(isCheck(checkurl+"..;/")) {
            ScanLists.add(checkurl+"..;/");
        }
        if(url.getPath().endsWith("/")){
            if(isCheck(baseurl+path)){
                ScanLists.add((baseurl+path));
            }
        }
        if (paths.length >= 3){
            for(int i=1;i< paths.length-1;i++){
                checkurl = checkurl + paths[i] + "/";
                cross = cross + "..;/";
                String CrossUrl = checkurl + cross;
                if(isCheck(checkurl)){
                    ScanLists.add(checkurl);
                }
                if(isCheck(CrossUrl)){
                    ScanLists.add(CrossUrl);
                }
            }
        }
        return ScanLists;
    }
    public static Boolean isCheck(String url){
        String urlmd5 = Common.MD5(url);
        if (scannedUrls.contains(urlmd5)){
            stdout.println("已扫描,跳过: "+ url);
            return false;
        }else{
            scannedUrls.add(urlmd5);
            return true;
        }
    }

    public static IHttpRequestResponse hadoopscan(List<String> scanlists,List headers,IHttpRequestResponse baseRequestResponse){
        for(String scanlist:scanlists){
            for(String hadooppoc:hadoop.get(0)){
                String exp = "GET " + scanlist.replace(baseurl,"") + hadooppoc + " HTTP/1.1";
                stdout.println("hadoopscan exp: "+ exp);
                headers.set(0,exp);
                byte[] body = helpers.buildHttpMessage(headers, null);
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), body);
                int bodyOffset = helpers.analyzeResponse(requestResponse.getResponse()).getBodyOffset();
                String resp =new  String(requestResponse.getResponse());
                String respbody = resp.substring(bodyOffset);
                for(String key:hadoop.get(1)){
                    if(respbody.contains(key)){
                        List<String> acturl = hadoop.get(2);
                        acturl.add(baseurl);
                        hadoop.set(2,acturl);
                        return requestResponse;
                    }
                }
            }
        }
        return null;
    }


}
