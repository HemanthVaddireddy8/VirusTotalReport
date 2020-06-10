using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.IO;
using System.Threading;
using System.Web.UI.WebControls;
using VirusTotalNET;
using VirusTotalNET.Results;
using VirusTotalReport;
using Newtonsoft.Json;
using System.Text;

namespace VirusTotalReport
{
    public partial class HomePage : System.Web.UI.Page
    {
        private string strPathToSaveFile= "";
        private string strFileNameFormat = "";
        //string path = @"C:\Users\heman\Downloads\small_apk_dataset.tar\VirusTotalResponses\Fusob\" + "ransom_fusob_" + fileName + ".json";

        protected void Page_Load(object sender, EventArgs e)
        {

        }

        //protected void btnGenerateReport_Click(object sender, EventArgs e)
        //{
        //    VirusTotal vt = new VirusTotal("43527801f0b977b98f24c37854daf87135f42e94e3f0df9b013b8c2bac535420");
        //    vt.UseTLS = true;
        //    string path = @"C:\Users\heman\Downloads\small_apk_dataset.tar\small_apk_dataset\Fusob\variety1\03f2f8b2eb7930b6049ad4e5f1e2b5a3.apk";
        //    var fileInfo = new FileInfo(path);

        //    var generatedReport = vt.GetFileReportAsync(fileInfo);

        //    //var scanResult = vt.ScanFileAsync(fileInfo);
        //    //var result = scanResult.Result;
        //    //var scanID = result.ScanId;

        //    //var report = vt.GetFileReportAsync(result.ScanId);
        //    //var fileReport = report.Result;

        //    var scans = generatedReport.Result.Scans;

        //    var totalAV = scans.Count;
        //    var totalDetectedAVs = 0;
        //    var listResults = new List<Result>();
        //    var objResult = new Result();

        //    foreach (var item in scans) {
        //        var key = item.Key;
        //        var value = item.Value;

        //        var objChildResult = new Result();
        //        var AVName = key.ToString();
        //        var AVDetected = value.Detected.ToString() == "False" ? 0 : 1;

        //        if (value.Detected.ToString() != "False") {
        //            totalDetectedAVs++;
        //        }

        //        objChildResult.Key = AVName;
        //        objChildResult.Value = AVDetected;
        //        listResults.Add(objChildResult);
        //    }

        //    //Detect Count
        //    objResult.Key = "Detect_Count";
        //    objResult.Value = totalDetectedAVs;
        //    listResults.Add(objResult);

        //    //Total Count
        //    objResult.Key = "total_av";
        //    objResult.Value = totalAV;
        //    listResults.Add(objResult);

        //    //Accuracy
        //    objResult.Key = "accuracy";
        //    objResult.Value = totalAV / totalDetectedAVs;
        //    listResults.Add(objResult);

        //    var listCount = listResults.Count;
        //    for (int i = 0; i < 3; i++) {
        //        var index = listCount - 1;
        //        var obj = listResults[index];
        //        listResults.RemoveAt(index);
        //        listResults.Insert(i, obj);
        //    }

        //    var json = JsonConvert.SerializeObject(listResults);
        //    txtResults.Text = json;
        //}

        public string GetAPKReport()
        {
            VirusTotal vt = new VirusTotal("43527801f0b977b98f24c37854daf87135f42e94e3f0df9b013b8c2bac535420");
            vt.UseTLS = true;
            //string path = @"C:\Users\heman\Downloads\small_apk_dataset.tar\small_apk_dataset\Fusob\variety1\03f2f8b2eb7930b6049ad4e5f1e2b5a3.apk";

            var fileInfo = new FileInfo(txtAPK.Text);//OATFileUpload.PostedFile.FileName));

            var generatedReport = vt.GetFileReportAsync(fileInfo);

            var scans = generatedReport.Result.Scans;

            var totalAV = scans.Count;
            var totalDetectedAVs = 0;
            var strReport = new StringBuilder();

            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                if (value.Detected.ToString() != "False")
                {
                    totalDetectedAVs++;
                }
            }

            strReport.Append("\"apk\":{");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"Detect_Count\":" + totalDetectedAVs + ",");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"total_av\":" + totalAV + ",");
            strReport.Append(Environment.NewLine);
            float d = (float)totalDetectedAVs/(float)totalAV;
            strReport.Append("\t\"accuracy\":" + d + ",");
            strReport.Append(Environment.NewLine);

            var listClassAPK = new List<classAPK>();
            var obj = new classAPKJson();
            int i = 1;
            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                var AVName = key.ToString();
                var AVDetected = value.Detected.ToString() == "False" ? 0 : 1;
                
                if (i == scans.Count)
                {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected);
                }
                else {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected + ",");
                }
                i++;
                strReport.Append(Environment.NewLine);
                obj.apkResult = strReport.ToString();
            }
            strReport.Append("\t},");

            var APKjson = JsonConvert.SerializeObject(obj);
            return strReport.ToString();
        }

        public string GetDEXReport()
        {
            VirusTotal vt = new VirusTotal("43527801f0b977b98f24c37854daf87135f42e94e3f0df9b013b8c2bac535420");
            vt.UseTLS = true;
            //string path = @"C:\Users\heman\Downloads\small_apk_dataset.tar\small_apk_dataset\Fusob\variety1\03f2f8b2eb7930b6049ad4e5f1e2b5a3.apk";
            var fileInfo = new FileInfo(txtDEX.Text);//OATFileUpload.PostedFile.FileName));

            var generatedReport = vt.GetFileReportAsync(fileInfo);

            var scans = generatedReport.Result.Scans;

            var totalAntiViruses = scans.Count;
            var totalDetectedAVs = 0;
            var strReport = new StringBuilder();

            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                if (value.Detected.ToString() != "False")
                {
                    totalDetectedAVs++;
                }
            }
            float d = (float)totalDetectedAVs / (float)totalAntiViruses;
            var Accuracy = d;

            strReport.Append("\t\"dex\":{");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"Detect_Count\":" + totalDetectedAVs + ",");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"total_av\":" + totalAntiViruses + ",");
            strReport.Append(Environment.NewLine);
            
            strReport.Append("\t\"accuracy\":" + d + ",");
            strReport.Append(Environment.NewLine);

            var listClassAPK = new List<classAPK>();
            var obj = new classAPKJson();
            int i = 1;
            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                var AVName = key.ToString();
                var AVDetected = value.Detected.ToString() == "False" ? 0 : 1;
                
                if (i == scans.Count)
                {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected);
                }
                else
                {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected + ",");
                }
                i++;

                strReport.Append(Environment.NewLine);
                obj.apkResult = strReport.ToString();
            }
            strReport.Append("\t},");

            var APKjson = JsonConvert.SerializeObject(obj);
            return strReport.ToString();
        }

        public string GetOATReport()
        {
            VirusTotal vt = new VirusTotal(APKFileUpload.PostedFile.FileName);//"43527801f0b977b98f24c37854daf87135f42e94e3f0df9b013b8c2bac535420");
            vt.UseTLS = true;
            
            var fileInfo = new FileInfo(txtOAT.Text);

            var generatedReport = vt.GetFileReportAsync(fileInfo);

            var scans = generatedReport.Result.Scans;

            var totalAV = scans.Count;
            var totalDetectedAVs = 0;
            var strReport = new StringBuilder();

            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                if (value.Detected.ToString() != "False")
                {
                    totalDetectedAVs++;
                }
            }

            strReport.Append("\t\"oat\":{");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"Detect_Count\":" + totalDetectedAVs + ",");
            strReport.Append(Environment.NewLine);
            strReport.Append("\t\"total_av\":" + totalAV + ",");
            strReport.Append(Environment.NewLine);
            float d = (float)totalDetectedAVs / (float)totalAV;
            strReport.Append("\t\"accuracy\":" + d + ",");
            strReport.Append(Environment.NewLine);

            var listClassAPK = new List<classAPK>();
            var obj = new classAPKJson();
            int i = 1;
            foreach (var item in scans)
            {
                var key = item.Key;
                var value = item.Value;

                var AVName = key.ToString();
                var AVDetected = value.Detected.ToString() == "False" ? 0 : 1;
                if (i == scans.Count)
                {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected);
                }
                else
                {
                    strReport.Append("\t" + '"' + key + '"' + ":" + AVDetected + ",");
                }
                i++;
                strReport.Append(Environment.NewLine);
                obj.apkResult = strReport.ToString();
            }
            strReport.Append("\t}");

            var APKjson = JsonConvert.SerializeObject(obj);
            return strReport.ToString();
        }

        protected void btnGenerateReport_Click(object sender, EventArgs e) {
            var APKResponse = GetAPKReport();
            var DEXResponse = GetDEXReport();
            var OATResponse = GetOATReport();

            var strFinalResult = new StringBuilder();
            strFinalResult.Append("{");
            strFinalResult.Append(Environment.NewLine);
            strFinalResult.Append("\t" + APKResponse);
            strFinalResult.Append(Environment.NewLine);
            strFinalResult.Append(DEXResponse);
            strFinalResult.Append(Environment.NewLine);
            strFinalResult.Append(OATResponse);
            strFinalResult.Append(Environment.NewLine);
            strFinalResult.Append("}");

            txtResults.Text = strFinalResult.ToString();
        }

        protected void btnSave_Click(object sender, EventArgs e)
        {
            string fileName = APKFileUpload.PostedFile.FileName;
            fileName = fileName.Substring(0, fileName.Length - 3);

            string path = strPathToSaveFile + strFileNameFormat + fileName + ".json";
            using (var tw = new StreamWriter(path, true))
            {
                tw.WriteLine(txtResults.Text);
            }
        }
    }
}