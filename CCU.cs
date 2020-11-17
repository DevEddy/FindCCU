namespace FindCCU
{
    public class CCU
    {
        public string Host { get; set; }
        public string Payload { get; set; }

        public override string ToString()
        {
            return $"{Host}: {Payload}";
        }
    }
}
