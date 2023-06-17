from client import Manager, Logger

if __name__ == '__main__':
    try:
        manager = Manager(server_ip="localhost", 
                         server_port=3000, 
                         programs_folder="client/src")
    except Exception as e:
        Logger.error(e)

