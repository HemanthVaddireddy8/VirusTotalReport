using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace VirusTotalReport
{
    public class Apk
    {
        public int detect_count { get; set; }
        public int total_av { get; set; }
        public double accuracy { get; set; }
        public int kaspersky { get; set; }
        public int avast { get; set; }
        public int bitdefender { get; set; }
        public int mcafee { get; set; }
        public int norton { get; set; }
        public int symantec { get; set; }
        public int sophos { get; set; }
    }

    public class Dex
    {
        public int detect_count { get; set; }
        public int total_av { get; set; }
        public double accuracy { get; set; }
        public int kaspersky { get; set; }
        public int avast { get; set; }
        public int bitdefender { get; set; }
        public int mcafee { get; set; }
        public int norton { get; set; }
        public int symantec { get; set; }
        public int sophos { get; set; }
    }

    public class Oat
    {
        public int detect_count { get; set; }
        public int total_av { get; set; }
        public double accuracy { get; set; }
        public int kaspersky { get; set; }
        public int avast { get; set; }
        public int bitdefender { get; set; }
        public int mcafee { get; set; }
        public int norton { get; set; }
        public int symantec { get; set; }
        public int sophos { get; set; }
    }

    public class RootObject
    {
        public Apk apk { get; set; }
        public Dex dex { get; set; }
        public Oat oat { get; set; }
    }
}