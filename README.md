# Secure Comms with Authentication

O projeto consiste no desenho e implementação de um protocolo que permita a comunicação segura entre dois pontos, com autenticação mútua.
Pretende-se que seja possı́vel trocar um ficheiro entre o cliente e o servidor usando o protocolo, caso o servidor considere que o utilizador tem essas permissões.
O utente pode-se autenticar com senhas diretas ou com o cartão de cidadão.
O servidor deverá conseguir provar a sua identidade, evintando-se ataques de MiTM ou impersonação

## Main objectives:

### Architecture:
- [ x ] Protocolo (planeamento e descrição) para a autenticação de utentes através de um mecanismo de desafio resposta (não é necessário considerar o registo online dos clientes)
- [ x ] Mecanismo para controlo de acesso, que permita indicar explicitamente se um utente pode ou não transferir ficheiros
- [ x ] Protocolo (planeamento e descrição) para a autenticação de utentes através do cartão de cidadão
- [ x ] Protocolo (planeamento e descrição) para a autenticação do servidor utilizando certificados X.509

### Implementation:
- [ x ] Protocolo para autenticação de utentes através da apresentação de senhas
- [ x ] Mecanismo para controlo de acesso
- [  ] Protocolo para autenticação de utentes através do cartão de cidadão
- [  ] Protocolo para autenticação do servidor através de certificados X.509

### Bonus Points:
- [  ] Outros mecanismos que confiram maior segurança ao sistema (Opcional)  
    - [  ] Hash( Hash (Salt + Password) + Nonce ) -> Secure senha

## Report:
O relatório deverá descrever o protocolo e demonstrar o funcionamento de cada uma das 4 funcionalidade + capturas de ecrã  

## Bibliography:
 * [Slides 5 and 6](https://joao.barraca.pt/teaching/sio/2019/)
 * Cryptography.io
 * [PyKCS11](https://github.com/LudovicRousseau/PyKCS11)