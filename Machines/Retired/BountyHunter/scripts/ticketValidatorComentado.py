#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):  # i: Numero de la linea         x: Contenido de la linea 
        if i == 0:
            if not x.startswith("# Skytrain Inc"): # Primera linea
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):  # Segunda linea
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):       # Tercera linea
            code_line = i+1
            continue

        if code_line and i == code_line:           # Cuarta linea
            if not x.startswith("**"):             # Tiene que empezar con **
                return False
            ticketCode = x.replace("**", "").split("+")[0] # Tiene que tener un +
            if int(ticketCode) % 7 == 4:           # El primer operando de la suma tiene que tener resto 4 al dividirlo entre 7        x * 7 + 4 = ticketCode
                validationNumber = eval(x.replace("**", "")) # Evalua la expresion completa quitando **
                if validationNumber > 100:         # Hemos conseguido que se evalue por lo que esta validacion no nos importa
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")   # Introducimos la ruta de un archivo
    ticket = load_file(fileName)                   # Comprueba que la extension del archivo sea md
    #DEBUG print(ticket)
    result = evaluate(ticket) 
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
