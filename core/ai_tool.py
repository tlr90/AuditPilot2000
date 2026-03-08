import ollama

class AI_Analyzer:
    
    def __init__(self, log_func=None):
        """
        :self.log_func: Function to print text to the dashboard GUI 
        """
        self.log_func = log_func
    
    def log(self, message):
        """
        Helper to decide where to send text.
        """
        if self.log_func:
            self.log_func(message)
        else:
            print(message)

    def ask_ai_for_remidiation(self, promt_or_resource):
        """
        Docstring for ask_ai_for_remidiation
        This is the prompt generator that interacts with the AI model. This sets the 
        model used and accepts the prompts generated from the other modules.
        It generates text as it works instead of waiting until the entire output is ready.

        """
        self.log_func(f"Consulting AI...\n")

        stream = ollama.chat(
            model='llama3.1:8b',
            messages=[{'role':'user', 'content': promt_or_resource}],
            stream=True
        )
        full_response = ""
        for chunk in stream:
            if getattr(self.log_func, "__self__", None) and getattr(self.log_func.__self__, "stop_requested", False):
                self.log_func("[!]AI stream interrupted by user.\n")
                break
            content = chunk['message']['content']
            self.log_func(content)
            full_response += content
        self.log_func("Analysis complete.\n", force_line=True)
        
        return full_response