using System;
using System.Collections.Generic;

namespace TA_ETW
{
    public class EtwConfig
    {
        public List<EtwTrace> Traces = new List<EtwTrace>();
    }
    public class EtwTrace
    {
        public string Name;
        public string Provider;
        public string Index = "";
        public string SourceType = "";
        public List<EtwEvent> Events = new List<EtwEvent>();
    }
    public class EtwEvent
    {
        public int Id;
        public List<EtwField> Fields = new List<EtwField>();
    }
    public class EtwField
    {
        public string Name;
        public Boolean IsField = true;
        public Boolean IsTimestamp = false;
        public Boolean IsLiteral = false;
        public string LiteralValue;
        public FieldExtractionMethod ExtractionMethod;
        public Dictionary<FilterType, List<String>> Filters; // = new Dictionary<FilterType, List<string>>();
        public EtwFieldTransformation TransformationMethod;
        public string TranslationName;
        public Dictionary<int, string> FieldEnumeration; // = new Dictionary<int, string>();
    }
    public class EtwFieldTransformation
    {
        public TransformationType TransformationType;
        public string ReplaceOld;
        public string ReplaceNew;
        public string Regex;
        public string RegexReplacement;
        public int TrimNumber;
        public char TrimChar;
    }
    public enum TransformationType
    {
        Replace = 1,
        RegexReplace = 2,
        TrimNChars = 3,
        TrimChar = 4
    }
    public enum FilterType
    {
        StartsWith = 1,
        Contains = 2,
        EndsWith = 3
    }
    public enum FieldExtractionMethod
    {
        GetBinary = 1,
        GetAnsiString = 2,
        GetInt16 = 3,
        GetInt32 = 4,
        GetInt64 = 5,
        GetInt8 = 6,
        GetIPAddress = 7,
        GetUInt16 = 8,
        GetUInt32 = 9,
        GetUInt64 = 10,
        GetUInt8 = 11,
        GetUnicodeString = 12
    }
}
