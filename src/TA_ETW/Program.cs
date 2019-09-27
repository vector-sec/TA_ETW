using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.O365.Security.ETW;
using Splunk.ModularInputs;
using Newtonsoft.Json;
using YamlDotNet.Serialization;
using System.IO;
using System.Text.RegularExpressions;

namespace TA_ETW
{
    public class TA_ETW : ModularInput
    {
        public static int Main(string[] args)
        {
            return Run<TA_ETW>(args, DebuggerAttachPoints.StreamEvents);
            // Useful for debugging in Visual Studio directly
            //string yamlPath = @"C:\test.yaml";
            //string rawYaml = File.ReadAllText(yamlPath);
            //var deserializer = new DeserializerBuilder().Build();
            //var input = new StringReader(rawYaml);
            //var yaml_trace = deserializer.Deserialize<EtwConfig>(input);
            //StartTrace(yaml_trace);
            //return 0;
        }

        public static Dictionary<String, dynamic> ProcessEventRecord(EtwTrace etwtrace, IEventRecord r)
        {
            Dictionary<String, dynamic> rawEvent = new Dictionary<String, dynamic>();
            foreach (EtwEvent etwevent in etwtrace.Events)
            {
                dynamic value;
                if (etwevent.Id == r.Id)
                {
                    Boolean skip = false;
                    foreach (EtwField etwfield in etwevent.Fields)
                    {
                        // Order of processing
                        // Timestamps and literals
                        // Property value extraction
                        // Filtering
                        // Enumerations
                        // Transformations
                        // Translations
                        // Output

                        // Check for timestamp and literal fields in the config
                        if (etwfield.IsTimestamp)
                        {
                            value = DateTime.UtcNow.ToString("o");
                        }
                        else if (etwfield.IsLiteral)
                        {
                            value = etwfield.LiteralValue;
                        }
                        // Check if the config field is not a field of the ETW event and instead is a property of it
                        // This is useful for getting the Event's Id
                        else if (!etwfield.IsField)
                        {
                            value = r.GetType().GetProperty(etwfield.Name).GetValue(r, null);
                            value = Convert.ToString(value);
                        }
                        else
                        {
                            switch (etwfield.ExtractionMethod)
                            {
                                // Take the extraction method provided in the config and try to use it
                                case FieldExtractionMethod.GetBinary:
                                    // I haven't actually had a reason to use GetBinary myself.
                                    // This should return a string of hexadecimal values
                                    // For example if binaryretvalue = byte[] { 0x00, 0x01, 0x02, 0x03, 0xaa, 0xab }
                                    // valuestr will be: 00 01 02 03 AA AB
                                    if (r.TryGetBinary(etwfield.Name, out byte[] binaryretvalue))
                                    {
                                        value = binaryretvalue;
                                        string valuestr = "";
                                        for (int i = 0; i < value.Length; i++)
                                        {
                                            int c = value[i];
                                            valuestr += c.ToString("X2");
                                        }
                                        value = valuestr;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetAnsiString:
                                    if (r.TryGetAnsiString(etwfield.Name, out string ansiretvalue))
                                    {
                                        value = ansiretvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetInt16:
                                    if (r.TryGetInt16(etwfield.Name, out Int16 int16retvalue))
                                    {
                                        value = int16retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetInt32:
                                    if (r.TryGetInt32(etwfield.Name, out Int32 int32retvalue))
                                    {
                                        value = int32retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetInt64:
                                    if (r.TryGetInt64(etwfield.Name, out Int64 int64retvalue))
                                    {
                                        value = int64retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetInt8:
                                    if (r.TryGetInt8(etwfield.Name, out sbyte int8retvalue))
                                    {
                                        value = int8retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetIPAddress:
                                    if (r.TryGetIPAddress(etwfield.Name, out System.Net.IPAddress ipretvalue))
                                    {
                                        value = ipretvalue.ToString();
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetUInt16:
                                    if (r.TryGetUInt16(etwfield.Name, out UInt16 uint16retvalue))
                                    {
                                        value = uint16retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetUInt32:
                                    if (r.TryGetUInt32(etwfield.Name, out UInt32 uint32retvalue))
                                    {
                                        value = uint32retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetUInt64:
                                    if (r.TryGetUInt64(etwfield.Name, out UInt64 uint64retvalue))
                                    {
                                        value = uint64retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetUInt8:
                                    if (r.TryGetUInt8(etwfield.Name, out byte uint8retvalue))
                                    {
                                        value = uint8retvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                case FieldExtractionMethod.GetUnicodeString:
                                    if (r.TryGetUnicodeString(etwfield.Name, out string unicoderetvalue))
                                    {
                                        value = unicoderetvalue;
                                    }
                                    else
                                    {
                                        value = "";
                                        if (rawEvent.ContainsKey("error"))
                                        {
                                            rawEvent["error"] = rawEvent["error"] + String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                        else
                                        {
                                            rawEvent["error"] = String.Format("Error retreiving value for {0} with {1}. ", etwfield.Name, etwfield.ExtractionMethod);
                                        }
                                    }
                                    break;
                                default:
                                    value = String.Format("{0} has not been implemented yet :(", etwfield.ExtractionMethod);
                                    break;
                            }
                        }
                        // Filtering
                        if (etwfield.Filters != null)
                        {
                            foreach (var fieldfilter in etwfield.Filters)
                            {
                                switch (fieldfilter.Key)
                                {
                                    case FilterType.StartsWith:
                                        foreach (string criteria in fieldfilter.Value)
                                        {
                                            if (Convert.ToString(value).StartsWith(criteria))
                                            {
                                                skip = true;
                                            }
                                        }
                                        break;
                                    case FilterType.Contains:
                                        foreach (string criteria in fieldfilter.Value)
                                        {
                                            if (Convert.ToString(value).Contains(criteria))
                                            {
                                                skip = true;
                                            }
                                        }
                                        break;
                                    case FilterType.EndsWith:
                                        foreach (string criteria in fieldfilter.Value)
                                        {
                                            if (Convert.ToString(value).EndsWith(criteria))
                                            {
                                                skip = true;
                                            }
                                        }
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                        if (skip)
                        {
                            // This event is being skipped, break out of the foreach loop that's enumerating the fields for the event
                            break;
                        }
                        // Process enumeration for field from config (if any)
                        if (etwfield.FieldEnumeration != null)
                        {
                            if (etwfield.FieldEnumeration.ContainsKey(Convert.ToInt32(value)))
                            {
                                value = etwfield.FieldEnumeration[Convert.ToInt32(value)];
                            }
                            else
                            {
                                value = String.Format("Enumeration for field {0} not found with value {1}", etwfield.Name, value);
                            }
                        }
                        // Process transformation for field value from config (if any)
                        if (etwfield.TransformationMethod != null)
                        {
                            value = Convert.ToString(value);
                            switch (etwfield.TransformationMethod.TransformationType)
                            {
                                case TransformationType.Replace:
                                    value = value.Replace(etwfield.TransformationMethod.ReplaceOld, etwfield.TransformationMethod.ReplaceNew);
                                    break;
                                case TransformationType.RegexReplace:
                                    value = Regex.Replace(value, etwfield.TransformationMethod.Regex, etwfield.TransformationMethod.RegexReplacement);
                                    break;
                                case TransformationType.TrimNChars:
                                    value = value.Substring(0, value.Length - etwfield.TransformationMethod.TrimNumber);
                                    break;
                                case TransformationType.TrimChar:
                                    value = value.TrimEnd(etwfield.TransformationMethod.TrimChar);
                                    break;
                                default:
                                    break;
                            }
                        }
                        // Process translation of field name from config (if any)
                        if (etwfield.TranslationName != null)
                        {
                            rawEvent[etwfield.TranslationName] = value;
                        }
                        else
                        {
                            rawEvent[etwfield.Name] = value;
                        }
                    }
                    if (skip)
                    {
                        // Return nothing to signify that we're dropping this event
                        return null;
                    }
                }
            }
            return rawEvent;
        }

        // Useful for debugging in Visual Studio directly
        //public static void StartTrace(EtwConfig etwconfig)
        //{
        //    UserTrace trace = new UserTrace(String.Format("TA_ETW_{0}", Guid.NewGuid().ToString()));
        //    foreach (EtwTrace etwtrace in etwconfig.Traces)
        //    {
        //        if (etwtrace.Events.Count > 0)
        //        {
        //            var predicates = Filter.EventIdIs(etwtrace.Events[0].Id);
        //            if (etwtrace.Events.Count > 1)
        //            {
        //                foreach (EtwEvent item in etwtrace.Events.GetRange(1, etwtrace.Events.Count - 1))
        //                {
        //                    predicates = predicates.Or(Filter.EventIdIs(item.Id));
        //                }
        //            }
        //            EventFilter filter = new EventFilter(predicates);
        //            filter.OnEvent += (IEventRecord r) =>
        //            {
        //                var rawEvent = ProcessEventRecord(etwtrace, r);
        //                if (rawEvent.Keys.Count > 0)
        //                {
        //                    Console.WriteLine(JsonConvert.SerializeObject(rawEvent));
        //                }
        //            };
        //            Provider provider = new Provider(etwtrace.Provider);
        //            provider.AddFilter(filter);
        //            trace.Enable(provider);
        //            Console.WriteLine(String.Format("Starting trace {0}", etwtrace.Name));
        //        }
        //    }
        //    if (etwconfig.Traces.Count > 0)
        //    {
        //        Helpers.SetupCtrlC(trace);
        //        trace.Start();
        //    }
        //    return;
        //}

        public override Scheme Scheme => new Scheme
        {
            Title = "TA_ETW",
            Description = "",
            Arguments = new List<Argument>
            {
                new Argument
                {
                    Name = "yaml_config_path",
                    Description = "Path to YAML config file",
                    DataType = DataType.String,
                    RequiredOnCreate = true
                }
            }
        };

        public override async Task StreamEventsAsync(InputDefinition inputDefinition, EventWriter eventWriter)
        {
            var splunk_home = Environment.GetEnvironmentVariable("SPLUNK_HOME");
            string yamlPath = ((SingleValueParameter)inputDefinition.Parameters["yaml_config_path"]).ToString();
            yamlPath = yamlPath.Replace("$SPLUNK_HOME", splunk_home);
            string rawYaml = File.ReadAllText(yamlPath);
            var deserializer = new DeserializerBuilder().Build();
            var input = new StringReader(rawYaml);
            var etwconfig = deserializer.Deserialize<EtwConfig>(input);
            UserTrace trace = new UserTrace(String.Format("TA_ETW_{0}", Guid.NewGuid().ToString()));
            foreach (EtwTrace etwtrace in etwconfig.Traces)
            {
                if (etwtrace.Events.Count > 0)
                {
                    var predicates = Filter.EventIdIs(etwtrace.Events[0].Id);
                    if (etwtrace.Events.Count > 1)
                    {
                        foreach (EtwEvent item in etwtrace.Events.GetRange(1, etwtrace.Events.Count - 1))
                        {
                            predicates = predicates.Or(Filter.EventIdIs(item.Id));
                        }
                    }
                    EventFilter filter = new EventFilter(predicates);
                    filter.OnEvent += (IEventRecord r) => {
                        //eventWriter.LogAsync(Severity.Debug, "Handing raw data off for processing");
                        var rawEvent = ProcessEventRecord(etwtrace, r);
                        if (rawEvent != null)
                        {
                            if (rawEvent.Keys.Count > 0)
                            {
                                //eventWriter.LogAsync(Severity.Debug, "Not a blank event, let's write it to Splunk");
                                //Console.WriteLine(JsonConvert.SerializeObject(rawEvent));
                                if (etwtrace.Index.Length > 0 && etwtrace.SourceType.Length > 0)
                                {
                                    //eventWriter.LogAsync(Severity.Debug, "Writing to index and sourcetype defined in YAML");
                                    eventWriter.QueueEventForWriting(new Event
                                    {
                                        Stanza = inputDefinition.Name,
                                        Index = etwtrace.Index,
                                        Data = JsonConvert.SerializeObject(rawEvent),
                                        SourceType = etwtrace.SourceType
                                    });
                                }
                                else
                                {
                                    if (etwtrace.Index.Length > 0)
                                    {
                                        //eventWriter.LogAsync(Severity.Debug, "Writing to index defined in YAML");
                                        eventWriter.QueueEventForWriting(new Event
                                        {
                                            Stanza = inputDefinition.Name,
                                            Index = etwtrace.Index,
                                            Data = JsonConvert.SerializeObject(rawEvent)
                                        });
                                    }
                                    else
                                    {
                                        if (etwtrace.SourceType.Length > 0)
                                        {
                                            //eventWriter.LogAsync(Severity.Debug, "Writing to sourcetype defined in YAML");
                                            eventWriter.QueueEventForWriting(new Event
                                            {
                                                Stanza = inputDefinition.Name,
                                                SourceType = etwtrace.SourceType,
                                                Data = JsonConvert.SerializeObject(rawEvent)
                                            });
                                        }
                                        else
                                        {
                                            //eventWriter.LogAsync(Severity.Debug, "Writing to index defined in inputs.conf stanza");
                                            eventWriter.QueueEventForWriting(new Event
                                            {
                                                Stanza = inputDefinition.Name,
                                                Data = JsonConvert.SerializeObject(rawEvent)
                                            });
                                        }
                                    }   
                                }
                            }
                        }
                    };
                    Provider provider = new Provider(etwtrace.Provider);
                    provider.AddFilter(filter);

                    ;
                    trace.Enable(provider);
                    Helpers.SetupCtrlC(trace);
                    Console.WriteLine("Starting trace");
                    await eventWriter.LogAsync(Severity.Debug, String.Format("Enabling config trace named {0} on the provider {1}", etwtrace.Name, etwtrace.Provider));
                    
                }
            }
            Helpers.SetupCtrlC(trace);
            await eventWriter.LogAsync(Severity.Debug, String.Format("Starting ETW trace"));
            trace.Start();
        }
    }
}