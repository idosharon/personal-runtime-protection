from client import Manager, Logger

if __name__ == '__main__':
    try:
        manger = Manager("localhost", 1234, programs_folder="client/src")
        p = manger.getPort()

    except Exception as e:
        Logger.error(e)

