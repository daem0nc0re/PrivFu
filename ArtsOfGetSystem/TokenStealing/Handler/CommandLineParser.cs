using System;
using System.Collections.Generic;
using System.Text;

namespace TokenStealing.Handler
{
    internal class CommandLineParser
    {
        private class CommandLineOption
        {
            readonly OptionType Type;
            readonly bool IsRequired;
            bool IsParsed;
            readonly string BriefName;
            readonly string FullName;
            bool Flag;
            string Value;
            readonly string Description;

            public CommandLineOption(
                bool _isRequired,
                string _briefName,
                string _fullName,
                string _description)
            {
                this.Type = OptionType.Flag;
                this.IsRequired = _isRequired;
                this.IsParsed = false;
                this.BriefName = _briefName;
                this.FullName = _fullName;
                this.Flag = false;
                this.Value = null;
                this.Description = _description;
            }

            public CommandLineOption(
                bool _isRequired,
                string _briefName,
                string _fullName,
                string _value,
                string _description)
            {
                if (_briefName != _fullName)
                    this.Type = OptionType.Parameter;
                else
                    this.Type = OptionType.Argument;

                this.IsRequired = _isRequired;
                this.IsParsed = false;
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
                if (this.Type != OptionType.Flag)
                    throw new InvalidOperationException(string.Format(
                        "{0} option is not flag option.",
                        this.FullName));
                return this.Flag;
            }

            public string GetFullName()
            {
                return this.FullName;
            }

            public bool GetIsParsed()
            {
                return this.IsParsed;
            }

            public bool GetIsRequired()
            {
                return this.IsRequired;
            }

            public OptionType GetOptionType()
            {
                return this.Type;
            }

            public string GetValue()
            {
                if (this.Type == OptionType.Flag)
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

        private enum OptionType
        {
            Flag,
            Parameter,
            Argument
        }

        private string g_Title = null;
        private string g_OptionName = null;
        private readonly List<CommandLineOption> g_Options =
            new List<CommandLineOption>();
        private readonly List<List<string>> g_Exclusive = new List<List<string>>();


        public void AddArgument(
            bool isRequired,
            string name,
            string description)
        {
            foreach (var opt in g_Options)
            {
                if (opt.GetBriefName() == name || opt.GetFullName() == name)
                {
                    throw new InvalidOperationException(string.Format(
                        "[!] {0} option is defined multiple times.\n",
                        name));
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                name,
                name,
                null,
                description);

            g_Options.Add(newOption);
        }


        public void AddFlag(
            bool isRequired,
            string briefName,
            string fullName,
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
                    throw new InvalidOperationException(string.Format(
                        "[!] {0} option is defined multiple times.\n",
                        fullName));
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                briefName,
                fullName,
                description);

            g_Options.Add(newOption);
        }


        public void AddParameter(
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
                    throw new InvalidOperationException(string.Format(
                        "[!] {0} option is already defined.\n",
                        fullName));
                }
            }

            CommandLineOption newOption = new CommandLineOption(
                isRequired,
                briefName,
                fullName,
                value,
                description);

            g_Options.Add(newOption);
        }


        public void AddExclusive(List<string> exclusive)
        {
            g_Exclusive.Add(exclusive);
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
                throw new InvalidOperationException(string.Format("[!] {0}\n", ex.Message));
            }

            throw new InvalidOperationException("[!] Option is not found.\n");
        }


        public void GetHelp()
        {
            StringBuilder usage = new StringBuilder();
            if (g_Title != null)
            {
                Console.WriteLine("\n{0}", g_Title);
            }

            if (g_OptionName != null)
            {
                usage.Append(string.Format(
                    "\nUsage: {0} {1} [Options]",
                    AppDomain.CurrentDomain.FriendlyName,
                    g_OptionName));
            }
            else
            {
                usage.Append(string.Format(
                    "\nUsage: {0} [Options]",
                    AppDomain.CurrentDomain.FriendlyName));
            }


            foreach (var opt in g_Options)
            {
                if (opt.GetOptionType() == OptionType.Argument)
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
                throw new InvalidOperationException(string.Format("[!] {0}\n", ex.Message));
            }

            throw new InvalidOperationException("[!] Option is not found.\n");
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
                if (opt.GetOptionType() == OptionType.Argument)
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
                if (opt.GetOptionType() == OptionType.Argument)
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


        public string[] Parse(string[] args)
        {
            StringBuilder exceptionMessage = new StringBuilder();
            List<string> reminder = new List<string>();

            for (var idx = 0; idx < args.Length; idx++)
            {
                foreach (var opt in g_Options)
                {
                    if ((opt.GetBriefName() == args[idx] || opt.GetFullName() == args[idx]) &&
                        (opt.GetOptionType() == OptionType.Flag))
                    {
                        if (opt.GetIsParsed())
                        {
                            exceptionMessage.Append(string.Format(
                                "[!] {0} option is declared multiple times.\n",
                                opt.GetFullName()));

                            throw new ArgumentException(exceptionMessage.ToString());
                        }

                        opt.SetIsParsed();
                        opt.SetFlag();
                        args[idx] = null;

                        break;
                    }
                    else if ((opt.GetBriefName() == args[idx] || opt.GetFullName() == args[idx]) &&
                        (opt.GetOptionType() == OptionType.Parameter))
                    {
                        if (opt.GetIsParsed())
                        {
                            exceptionMessage.Append(string.Format(
                                "[!] {0} option is declared multiple times.\n",
                                opt.GetFullName()));

                            throw new ArgumentException(exceptionMessage.ToString());
                        }

                        if (idx + 1 >= args.Length)
                        {
                            exceptionMessage.Append(string.Format(
                                "[!] Missing the value for {0} option.\n",
                                opt.GetBriefName()));

                            throw new ArgumentException(exceptionMessage.ToString());
                        }

                        opt.SetIsParsed();
                        args[idx] = null;
                        opt.SetValue(args[++idx]);
                        args[idx] = null;

                        break;
                    }
                }

                if (args[idx] != null)
                {
                    foreach (var opt in g_Options)
                    {
                        if (opt.GetOptionType() == OptionType.Argument &&
                            !opt.GetIsParsed())
                        {
                            opt.SetIsParsed();
                            opt.SetValue(args[idx]);
                            args[idx] = null;

                            break;
                        }
                    }
                }

                if (args[idx] != null)
                    reminder.Add(args[idx]);
            }

            foreach (var opt in g_Options)
            {
                if (opt.GetIsRequired() && !opt.GetIsParsed())
                {
                    exceptionMessage.Append(string.Format(
                        "[!] {0} option is required.\n",
                        opt.GetBriefName()));

                    throw new ArgumentException(exceptionMessage.ToString());
                }
            }

            int exclusiveCounter;
            string fullName;

            foreach (var exclusiveList in g_Exclusive)
            {
                exclusiveCounter = 0;

                foreach (var exclusive in exclusiveList)
                {
                    fullName = string.Format("--{0}", exclusive.TrimStart('-'));

                    foreach (var opt in g_Options)
                    {
                        if (opt.GetFullName() == fullName && opt.GetIsParsed())
                            exclusiveCounter++;
                    }
                }

                if (exclusiveCounter > 1)
                {
                    exceptionMessage.Append("[!] Following options should not be set at a time:\n\n");

                    foreach (var exclusive in exclusiveList)
                    {
                        fullName = string.Format("--{0}", exclusive.TrimStart('-'));

                        exceptionMessage.Append(string.Format("\t+ {0} option\n", fullName));
                    }

                    throw new ArgumentException(exceptionMessage.ToString());
                }
            }

            return reminder.ToArray();
        }


        public void SetOptionName(string optionName)
        {
            g_OptionName = optionName;
        }


        public void SetTitle(string title)
        {
            g_Title = title;
        }
    }
}
