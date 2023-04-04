class RSA:
    """
    RSA Algorithm Class
    Uses: to encrypt and decrypt text using RSA, retrieve public and private keys
    """
    
    # generated 3 large primes, hardcoded
    Q = 41919707
    P = 48227741
    E = 96903953

    def recieve_private_key(p, q, e):
        d = RSA.__calculate_d_value(p, q, e)
        m = RSA.__calculate_m_value(p, q)
        kr = (d, m)
        return kr

    def recieve_public_key(p, q, e):
        m = RSA.__calculate_m_value(p, q)
        ku = (e, m)
        return ku
    
    def __calculate_m_value(p, q):
        return p * q 
    
    def __calculate_d_value(p, q, e):
        n = RSA.__calculate_n_value(p, q)
        multiplicative_inverse = pow(e, -1, n)
        return multiplicative_inverse

    def __calculate_n_value(p, q):
        return ( (p-1) * (q-1) )

    def left_to_right_method(b, e, m):
        
        e_binary = bin(e)
        e_binary = e_binary[2:]  
        
        temp_list = []
        first = True
        for bit in e_binary:
            if first:
                temp_list.append(1)
                first = False

            elif bit == '0':
                temp_list_last = temp_list[-1]
                next_x_value = int(temp_list_last)*2
                temp_list.append(next_x_value)

            elif bit == "1":
                temp_list_last = temp_list[-1]
                next_x_value = int(temp_list_last)*2
                temp_list.append(next_x_value)
                temp_list.append(next_x_value+1)

        #calculate remainder using the left-hand calculation method
        first = b**1 % m
        previous = first
        for i in range(1, len(temp_list)):
            e = temp_list[i] 
            #check if bit is 1 or 0
            if e == temp_list[i-1]+1 and i != len(temp_list):
                #x^n-1 * x^1
                final_val = (previous * first) % m
                previous = final_val    
            else:
                #prev. x^n * prev. x^n
                final_val = (previous * previous) % m
                previous = final_val
            
        return final_val

 
    def decryption(ciphertext, key):
        
        plain_text = ''

        #divide text into boxes of 8
        ciphertext_boxes = text_to_textboxes(ciphertext, 8, True, 'X')

        encoded_ciphertext_boxes = []
        for box in ciphertext_boxes:
            encoded_ciphertext_boxes.append(RSA.__encoding(box))
        
        lrm_encoded_ciphertext_boxes = []
        for codes_values in encoded_ciphertext_boxes:
            lrm_encoded_ciphertext_boxes.append(RSA.left_to_right_method(codes_values, key[0], key[1]))
        
        for codes_values in lrm_encoded_ciphertext_boxes:
            plain_text += RSA.__decoding(codes_values, 6)
        
            #remove leftover padding
            plain_text = plain_text.rstrip('X')
        
        return plain_text


    def encryption(plaintext, key):
        
        #divide text into boxes of 6
        cipher_text = ''
        plaintext_boxes = text_to_textboxes(plaintext, 6, True, 'X')
        
        encoded_plaintext_boxes = []
        for box in plaintext_boxes:
            encoded_plaintext_boxes.append(RSA.__encoding(box))

        lrm_encoded_plaintext_boxes = []
        for code_values in encoded_plaintext_boxes:
            lrm_encoded_plaintext_boxes.append(RSA.left_to_right_method(code_values, key[0], key[1]))
        
        for code_values in lrm_encoded_plaintext_boxes:
            cipher_text += RSA.__decoding(code_values, 8)
        
        return cipher_text


    def __decoding(code_values, size_of_box):
        
        text = ''

        #put strings in given box size and pad
        #n is the max number of letters
        n = 0
        i = 96**n
        while code_values > i:
            n += 1
            i = 96**n

        if size_of_box >= n:
            index_list = []
            while code_values!=0 and n != -1:
                if code_values == 96:
                    index_list.append(1)
                    index_list.append(0)
                    code_values -= 96
                
                else:
                    for i in range(97):
                        if code_values < i * (96**n):
                            index_list.append(i-1)
                            code_values -= (i-1) * (96**n)
                            n-=1
                            break
                        if i == 96:
                            index_list.append(1)
                            index_list.append(0)
                            code_values -= (i-1) * (96**n)
                            n-=1
                            break
                
            
            #get a base encoding
            lowercase_letters = "".join([chr(ord('a')+i) for i in range(26)])
            uppercase_letters = lowercase_letters.upper()
            decimal = "".join([str(i) for i in range(10)])
            special_chars = ''
            for i in range(ord('!'), 127):
                if not chr(i).isalnum():
                    special_chars += chr(i)
                    
            decoding_base_char = uppercase_letters + lowercase_letters + decimal + special_chars + ' \n'

            for indexes in index_list:
                text += decoding_base_char[indexes]
                        
            text = text.lstrip('A')
            
            if size_of_box > len(text):
                add = size_of_box - len(text)
                for i in range(add):
                    text = 'A' + text 
        
        return text


    def __encoding(text):
        encoded_value = 0
        
        #get a base encoding
        lowercase = "".join([chr(ord('a')+i) for i in range(26)])
        uppercase = lowercase.upper()
        decimal = "".join([str(i) for i in range(10)])
        special_char = ''
        for i in range(ord('!'), 127):
            if not chr(i).isalnum():
                special_char += chr(i)
                
        encoding_base_char = uppercase + lowercase + decimal + special_char + ' \n'
        
        #mult base by 96**n, n is decremented val of the length of text
        current_exponent = len(text) - 1
        prev_character = ''
        remove_prev_character = 0
        
        for char in text:    
            #this is a special case where B=96
            if char == 'A' and prev_character == 'B':
                encoded_value += 96
                encoded_value -= remove_prev_character
                current_exponent -= 1
                
            else:
                current_index = encoding_base_char.index(char)
                encoded_value += current_index * 96**current_exponent
                remove_prev_character = current_index * 96**current_exponent
                current_exponent -= 1
            
            prev_character = char
                
        return encoded_value


def text_to_textboxes(text, size_of_box, to_pad = False, padding_char = 'x'):
    """
    puts text into boxes (lists) to manipulate as chunks
    """

    temp_counter = 1
    temp_text = ''
    boxes = []
    
    for char in text:
        temp_text = temp_text + char
        
        if temp_counter == size_of_box:
            temp_counter = 1
            boxes.append(temp_text)
            temp_text = ''
            continue
        
        temp_counter += 1
    
    if to_pad == True and temp_text != '':
        padding_length = size_of_box - len(temp_text)
        for i in range(padding_length):
            temp_text = temp_text + padding_char
        boxes.append(temp_text)
    
    if to_pad == False and temp_text != '':
        boxes.append(temp_text)

    return boxes