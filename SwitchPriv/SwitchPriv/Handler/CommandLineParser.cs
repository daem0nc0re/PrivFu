using System;
using System.Collections.Generic;
using System.Text;

namespace SwitchPriv.Handler
{
    class CommandLineParser
    {
        private class CommandLineOption
        {
            readonly bool IsFlag;
            readonly bool IsRequired;
            bool IsParsed;
            readonly string BriefName;
            readonly string FullName;
            bool Flag;
            string Value;
            readonly string Description;

            public CommandLineOption(
                bool _isRequired,
                bool _isParsed,
                string _briefName,
                string _fullName,
                bool _flag,
                string _description)
            {
                this.IsFlag = true;
                this.IsRequired = _isRequired;
                this.IsParsed = _isParsed;
                this.BriefName = _briefName;
                this.FullName = _fullName;
                this.Flag = _flag;
                this.Value = string.Empty;
                this.Description = _description;
            }

            public CommandLineOption(
                bool _isRequired,
                bool _isParsed,
                string _briefName,
                string _fullName,
                string _value,
                string _description)
            {
                this.IsFlag = false;
                this.IsRequired = _isRequired;
                this.IsParsed = _isParsed;
                this.BriefName = _briefName;
                this.FullName = _fullName;
                this.Flag = false;
                this.Value = _value;
                this.Description = _description;
            }

            public string GetBriefName()
            {
                return this.BriefName;
            }

            public string GetDescription()
            {
                return this.Description;
            }

            public bool GetFlag()
            {
                if (!this.IsFlag)
                    throw new InvalidOperationException(string.Format(
                        "{0} option is not flag option.",
                        this.FullName));
                return this.Flag;
            }

            public string GetFullName()
            {
                return this.FullName;
            }

            public bool GetIsFlag()
            {
                return this.IsFlag;
            }

            public bool GetIsParsed()
            {
                return this.IsParsed;
            }

            public bool GetIsRequired()
            {
                return this.IsRequired;
            }

            public string GetValue()
            {
                if (this.IsFlag)
                    throw new InvalidOperationException(string.Format(
                        "{0} option is flag option.",
                        this.FullName));
                return this.Value;
            }

            public void SetFlag()
            {
                this.Flag = !this.Flag;
            }

            public void SetIsParsed()
            {
                this.IsParsed = true;
            }

            public void SetValue(string _value)
            {
                this.Value = _value;
            }
        }

        private string g_Title = string.Empty;
        private readonly List<CommandLineOption> g_Options =
            new List<CommandLineOption>();

        public void Add(
            bool isRequired,
            string name,
            string description)
        {
            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == name || opt.GetFullName() == name)
                {
                    return;
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                false,
                name,
                name,
                string.Empty,
                description);

            g_Options.Add(newOption);
        }

        public void Add(
            bool isRequired,
            string briefName,
            string fullName,
            bool flag,
            string description)
        {
            briefName = string.Format("-{0}", briefName);
            fullName = string.Format("--{0}", fullName);

            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == briefName ||
                    opt.GetFullName() == briefName ||
                    opt.GetBriefName() == fullName ||
                    opt.GetFullName() == fullName)
                {
                    return;
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                false,
                briefName,
                fullName,
                flag,
                description);

            g_Options.Add(newOption);
        }

        public void Add(
            bool isRequired,
            string briefName,
            string fullName,
            string value,
            string description)
        {
            briefName = string.Format("-{0}", briefName);
            fullName = string.Format("--{0}", fullName);

            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == briefName ||
                    opt.GetFullName() == briefName ||
                    opt.GetBriefName() == fullName ||
                    opt.GetFullName() == fullName)
                {
                    return;
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                false,
                briefName,
                fullName,
                value,
                description);

            g_Options.Add(newOption);
        }

        public bool GetFlag(string key)
        {
            try
            {
                foreach (var opt in g_Options)
                {
                    if (opt.GetFullName().TrimStart('-') == key)
                    {
                        return opt.GetFlag();
                    }
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine("\n[!] {0}\n", ex.Message);
                Environment.Exit(-1);
            }

            throw new ArgumentException("Option is not found.");
        }

        public void GetHelp()
        {
            StringBuilder usage = new StringBuilder();
            if (g_Title != string.Empty)
            {
                Console.WriteLine("\n{0}", g_Title);
            }

            usage.Append(string.Format(
                "\nUsage: {0} [Options]",
                AppDomain.CurrentDomain.FriendlyName));

            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == opt.GetFullName())
                {
                    if (opt.GetIsRequired())
                    {
                        usage.Append(string.Format(
                        " <{0}>",
                        opt.GetFullName()));
                    }
                    else
                    {
                        usage.Append(string.Format(
                        " [{0}]",
                        opt.GetFullName()));
                    }
                }
            }

            Console.WriteLine(usage);

            ListOptions();
        }

        public string GetValue(string key)
        {
            try
            {
                foreach (var opt in g_Options)
                {
                    if (opt.GetFullName().TrimStart('-') == key)
                    {
                        return opt.GetValue();
                    }
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine("\n[!] {0}\n", ex.Message);
                Environment.Exit(-1);
            }

            throw new ArgumentException("Option is not found.");
        }

        public void ListOptions()
        {
            string formatter;
            int maximumLength = 0;

            if (g_Options.Count == 0)
            {
                return;
            }

            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == opt.GetFullName())
                {
                    formatter = string.Format(
                        "{0}",
                        opt.GetFullName());
                }
                else
                {
                    formatter = string.Format(
                        "{0}, {1}",
                        opt.GetBriefName(),
                        opt.GetFullName());
                }

                if (formatter.Length > maximumLength)
                {
                    maximumLength = formatter.Length;
                }
            }

            formatter = string.Format("\t{{0,-{0}}} : {{1}}", maximumLength);
            Console.WriteLine();

            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == opt.GetFullName())
                {
                    Console.WriteLine(string.Format(
                        formatter,
                        opt.GetFullName(),
                        opt.GetDescription()));
                }
                else
                {
                    Console.WriteLine(string.Format(
                        formatter,
                        string.Format("{0}, {1}", opt.GetBriefName(), opt.GetFullName()),
                        opt.GetDescription()));
                }
            }

            Console.WriteLine();
        }

        public void Parse(string[] args)
        {
            for (var idx = 0; idx < args.Length; idx++)
            {
                foreach (var opt in g_Options)
                {
                    if (opt.GetIsParsed())
                        continue;

                    if ((opt.GetBriefName() == args[idx] || opt.GetFullName() == args[idx]) &&
                        opt.GetIsFlag())
                    {
                        opt.SetIsParsed();
                        opt.SetFlag();
                        break;
                    }
                    else if ((opt.GetBriefName() == args[idx] || opt.GetFullName() == args[idx]) &&
                        !opt.GetIsFlag() &&
                        opt.GetBriefName() != opt.GetFullName())
                    {
                        if (idx + 1 >= args.Length)
                        {
                            Console.WriteLine(
                                "\n[!] Missing the value for {0} option.\n",
                                opt.GetBriefName());
                            Environment.Exit(-1);
                        }

                        opt.SetIsParsed();
                        opt.SetValue(args[++idx]);
                        break;
                    }
                    else if (!opt.GetIsFlag() && opt.GetBriefName() == opt.GetFullName())
                    {
                        opt.SetIsParsed();
                        opt.SetValue(args[idx]);
                        break;
                    }
                }
            }

            foreach (var opt in g_Options)
            {
                if (opt.GetIsRequired() && !opt.GetIsParsed())
                {
                    GetHelp();
                    Console.WriteLine("\n[!] {0} option is required.\n", opt.GetBriefName());
                    Environment.Exit(-1);
                }
            }
        }

        public void SetTitle(string title)
        {
            g_Title = title;
        }
    }
}