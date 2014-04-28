using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Xml;
using AlexaAPI.Models;

namespace AlexaAPI.Controllers
{

    public class AWISClient
    {
        private static string SERVICE_HOST = "awis.amazonaws.com";
        private static string AWS_BASE_URL = "http://" + SERVICE_HOST + "/?";
        private static string HASH_ALGORITHM = "HmacSHA1";
        private static string DATEFORMAT_AWS = "yyyy-MM-ddTHH:mm:ss.fffZ";


        public string AccessKeyId { get; set; }
        public string SecretAccessKey { get; set; }

        public AWISClient(string accessKeyId, string secretAccessKey)
        {
            this.AccessKeyId = accessKeyId;
            this.SecretAccessKey = secretAccessKey;
        }

        /**
        * Generates a timestamp for use with AWS request signing
        *
        * @param date current date
        * @return timestamp
        */
        protected static String getTimestampFromLocalTime(DateTime date)
        {
            return date.ToUniversalTime().ToString(DATEFORMAT_AWS, System.Globalization.CultureInfo.InvariantCulture);
        }

        public String generateSignature(String data)
        {
            var shaiSignature = new HMACSHA1(Encoding.UTF8.GetBytes(this.SecretAccessKey));

            // calculate the hash
            var binSig = shaiSignature.ComputeHash(Encoding.UTF8.GetBytes(data));

            // convert to hex
            var signature = Convert.ToBase64String(binSig);

            return signature;
        }


        /**
         * Makes a request to the specified Url and return the results as a String
         *
         * @param requestUrl url to make request to
         * @return the XML document as a String
         * @throws IOException
         */
        private static String makeRequest(String requestUrl)
        {
            WebRequest wrGETURL;
            wrGETURL = WebRequest.Create(requestUrl);

            Stream objStream;
            objStream = wrGETURL.GetResponse().GetResponseStream();

            StreamReader objReader = new StreamReader(objStream);

            string sLine = "";
            int i = 0;
            string ret = string.Empty;

            while (sLine != null)
            {
                i++;
                sLine = objReader.ReadLine();

                ret += sLine;
            }

            return ret;
        }

        public static string UpperCaseUrlEncode(string s)
        {
            char[] temp = s.ToCharArray();
            for (int i = 0; i < temp.Length - 2; i++)
            {
                if (temp[i] == '%')
                {
                    temp[i + 1] = char.ToUpper(temp[i + 1]);
                    temp[i + 2] = char.ToUpper(temp[i + 2]);
                }
            }
            return new string(temp);
        }

        private string ToQueryString(NameValueCollection nvc)
        {
            var array = (from key in nvc.AllKeys
                         from value in nvc.GetValues(key)
                         select string.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(value)))
                .ToArray();
            return string.Join("&", array);
        }

        private String buildQuerySiteInfo(string site)
        {
            String timestamp = getTimestampFromLocalTime(DateTime.Now);

            NameValueCollection queryParams = new NameValueCollection();

            // BEWARE OF PARAMS ORDER.
            queryParams.Add("AWSAccessKeyId", this.AccessKeyId);
            queryParams.Add("Action", "UrlInfo");
            queryParams.Add("ResponseGroup", "Rank");
            queryParams.Add("SignatureMethod", HASH_ALGORITHM);
            queryParams.Add("SignatureVersion", "2");
            queryParams.Add("Timestamp", timestamp);
            queryParams.Add("Url", site);
            queryParams.Add("Version", "2005-07-11");

            return ToQueryString(queryParams);
        }

        private String buildQuerySitesLinkingIn(string site, int start, int count = 20)
        {
            String timestamp = getTimestampFromLocalTime(DateTime.Now);

            NameValueCollection queryParams = new NameValueCollection();

            // BEWARE OF PARAMS ORDER.
            queryParams.Add("AWSAccessKeyId", this.AccessKeyId);
            queryParams.Add("Action", "SitesLinkingIn");
            queryParams.Add("Count", count.ToString());
            queryParams.Add("ResponseGroup", "SitesLinkingIn");
            queryParams.Add("SignatureMethod", HASH_ALGORITHM);
            queryParams.Add("SignatureVersion", "2");
            queryParams.Add("Start", start.ToString());
            queryParams.Add("Timestamp", timestamp);
            queryParams.Add("Url", site);

            queryParams.Add("Version", "2005-07-11");

            return ToQueryString(queryParams);
        }

        private String buildQueryCategoryListings(string categories, int start, int count = 20)
        {
            String timestamp = getTimestampFromLocalTime(DateTime.Now);

            NameValueCollection queryParams = new NameValueCollection();

            // BEWARE OF PARAMS ORDER.
            queryParams.Add("AWSAccessKeyId", this.AccessKeyId);
            queryParams.Add("Action", "CategoryListings");
            queryParams.Add("Count", count.ToString());
            queryParams.Add("Path", categories);
            queryParams.Add("Recursive", "True");
            queryParams.Add("ResponseGroup", "Listings");
            queryParams.Add("SignatureMethod", HASH_ALGORITHM);
            queryParams.Add("SignatureVersion", "2");
            queryParams.Add("SortBy", "Popularity");
            queryParams.Add("Start", start.ToString());
            queryParams.Add("Timestamp", timestamp);
            queryParams.Add("Version", "2005-07-11");

            return ToQueryString(queryParams);
        }

        private String buildQueryCategoryBrowse(string categories)
        {
            String timestamp = getTimestampFromLocalTime(DateTime.Now);

            NameValueCollection queryParams = new NameValueCollection();


            // BEWARE OF PARAMS ORDER.
            queryParams.Add("AWSAccessKeyId", this.AccessKeyId);
            queryParams.Add("Action", "CategoryBrowse");
            queryParams.Add("Descriptions", "True");
            queryParams.Add("Path", categories);
            queryParams.Add("ResponseGroup", "Categories");
            queryParams.Add("SignatureMethod", HASH_ALGORITHM);
            queryParams.Add("SignatureVersion", "2");
            queryParams.Add("Timestamp", timestamp);
            queryParams.Add("Version", "2005-07-11");

            return ToQueryString(queryParams);
        }
        public string CategoryBrowse(string categories)
        {
            // Read command line parameters
            String query = UpperCaseUrlEncode(buildQueryCategoryBrowse(categories));

            return SignAndRequest(query);
        }
        public string CategoryListings(string categories, int start, int count = 20)
        {
            // Read command line parameters
            String query = UpperCaseUrlEncode(buildQueryCategoryListings(categories, start, count));

            return SignAndRequest(query);
        }
        public string SitesLinkingIn(string categories, int start, int count = 20)
        {
            // Read command line parameters
            String query = UpperCaseUrlEncode(buildQuerySitesLinkingIn(categories, start, count));
            
            return SignAndRequest(query);
        }
        public string UrlInfo(string url)
        {
            // Read command line parameters
            String query = UpperCaseUrlEncode(buildQuerySiteInfo(url));

            return SignAndRequest(query);
        }

        private string SignAndRequest(String query)
        {
            String toSign = "GET\n" + SERVICE_HOST + "\n/\n" + query;

            String signature = generateSignature(toSign);

            String uri = AWS_BASE_URL + query + "&Signature=" + UpperCaseUrlEncode(HttpUtility.UrlEncode(signature));

            // Make the Request

            String xmlResponse = makeRequest(uri);

            /* BEGIN BEAUTIFY This is not important. Only used for UI purposes.*/

            XmlDocument xmlDoc = new XmlDocument();

            xmlDoc.LoadXml(xmlResponse);
            xmlResponse = Beautify(xmlDoc);

            /* END BEAUTIFY */


            return xmlResponse;
        }

        static public string Beautify(XmlDocument doc)
        {
            StringBuilder sb = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.IndentChars = "  ";
            settings.NewLineChars = "\r\n";
            settings.NewLineHandling = NewLineHandling.Replace;
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                doc.Save(writer);
            }
            return sb.ToString();
        }
    }

    public class HomeController : Controller
    {

        public ActionResult Index()
        {
            var model = new IndexModel();

            // Intentionaly commented below so you see the compiler error and change to your own credentials.
            //String accessKey = "YOUR_ACCESS_KEY";
            //String secretKey = "YOUR_SECRET_KEY";

            string categories = "Top/Business/Automotive";

            AWISClient client = new AWISClient(accessKey, secretKey);

            string url = "http://codealike.com";

            model.UrlInfoData = client.UrlInfo(url);
            model.SitesLinkingInData = client.SitesLinkingIn("corvalius.com", 1);
            model.CategoryListingsData = client.CategoryListings(categories, 1);
            model.CategoryBrowseData = client.CategoryBrowse(categories);

            return View(model);
        }
    }
}