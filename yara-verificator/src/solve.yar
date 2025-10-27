rule http_c2_agent_sample
{
    strings:
        $user_agent = "Mozilla/5.0"
        $create_process = "CreateProcess"
        $wininet1 = "InternetOpen"
    condition:
	all of them
}
