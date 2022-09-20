#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    # Checks for .md extension and loads file
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for irregularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):  # i: Number of line, x: Content of the line 
        if i == 0:
            if not x.startswith("# Skytrain Inc"): # First line content
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):  # Second line content
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):       # Third line content
            code_line = i+1
            continue

        if code_line and i == code_line:           # Fourth line content
            if not x.startswith("**"):             # Has to start with **
                return False
            ticketCode = x.replace("**", "").split("+")[0] # Has to have a + sign
            if int(ticketCode) % 7 == 4:           # The first operand of the sum needs to have a 4 reminder when divided by 7,  'x * 7 + 4 = ticketCode'
                validationNumber = eval(x.replace("**", "")) # Evaluates the complete expression after removing the ** signs
                if validationNumber > 100:         # We have done the eval so this condiotion does not really matter
                    return True
                else:
                    return False
    return False

def main():
    # Main function
    fileName = input("Please enter the path to the ticket file.\n") 
    ticket = load_file(fileName)          
    #DEBUG print(ticket)
    result = evaluate(ticket) 
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close


main()