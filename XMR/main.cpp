/*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Additional permission under GNU GPL version 3 section 7
*
* If you modify this Program, or any covered work, by linking or combining
* it with OpenSSL (or a modified version of that library), containing parts
* covered by the terms of OpenSSL License and SSLeay License, the licensors
* of this Program grant you additional permission to convey the resulting work.
*
*/

#include "Executor.h"
#include "MineThread.h"
#include "jconf.h"
#include "console.h"
#include "donate-level.h"
#include "AutoAdjust.hpp"

#ifndef CONF_NO_HTTPD
#include "httpd.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//#ifndef CONF_NO_TLS
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#endif

//Do a press any key for the windows folk. *insert any key joke here*
#ifdef _WIN32
void win_exit()
{
    printer::inst()->print_str("Press any key to exit.");
    get_key();
    return;
}

#define strcasecmp _stricmp

#else
void win_exit() { return; }
#endif // _WIN32

void do_benchmark();

int main(int argc, char *argv[])
{
//#ifndef CONF_NO_TLS
//    SSL_library_init();
//    SSL_load_error_strings();
//    ERR_load_BIO_strings();
//    ERR_load_crypto_strings();
//    SSL_load_error_strings();
//    OpenSSL_add_all_digests();
//#endif

    const char* sFilename = "config.txt";
    bool benchmark_mode = false;

    if (argc >= 2)
    {
        if (strcmp(argv[1], "-h") == 0)
        {
            printer::inst()->print_msg(L0, "Usage %s [CONFIG FILE]", argv[0]);
            win_exit();
            return 0;
        }

        if (argc >= 3 && strcasecmp(argv[1], "-c") == 0)
        {
            sFilename = argv[2];
        }
        else if (argc >= 3 && strcasecmp(argv[1], "benchmark_mode") == 0)
        {
            sFilename = argv[2];
            benchmark_mode = true;
        }
        else
            sFilename = argv[1];
    }

    if (!jconf::inst()->parse_config(sFilename))
    {
        win_exit();
        return 0;
    }

    if (jconf::inst()->NeedsAutoconf())
    {
        AutoAdjust adjust;
        adjust.printConfig();
        win_exit();
        return 0;
    }

    if (!MineThread::self_test())
    {
        win_exit();
        return 0;
    }

    if (benchmark_mode)
    {
        do_benchmark();
        win_exit();
        return 0;
    }

#ifndef CONF_NO_HTTPD
    /* http port. */
    if (jconf::inst()->GetHttpdPort() != 0)
    {   /* Start a daemon thread to monitor the process. */
        if (!httpd::inst()->start_daemon()) 
        {
            win_exit();
            return 0;
        }
    }
#endif

    printer::inst()->print_str("-------------------------------------------------------------------\n");
    printer::inst()->print_str("XMR-Stak-CPU mining software, CPU Version.\n");
    printer::inst()->print_str("This is Michael Ding's Version.\n");
    printer::inst()->print_str("You can use following keys to display reports:\n");
    printer::inst()->print_str("'h' - hashrate\n");
    printer::inst()->print_str("'r' - results\n");
    printer::inst()->print_str("'c' - connection\n");
    printer::inst()->print_str("-------------------------------------------------------------------\n");

    /* Printer writes logs into the jconf::outputFile. */
    if (strlen(jconf::inst()->GetOutputFile()) != 0)
        printer::inst()->open_logfile(jconf::inst()->GetOutputFile());

    /* Start Executor. */
    Executor::inst()->ex_start(); /* ex_main */

    int key;
    while (true)
    {
        key = get_key();

        switch (key)
        {
        case 'h':
            Executor::inst()->push_event(ex_event(EV_USR_HASHRATE));
            break;
        case 'r':
            Executor::inst()->push_event(ex_event(EV_USR_RESULTS));
            break;
        case 'c':
            Executor::inst()->push_event(ex_event(EV_USR_CONNSTAT));
            break;
        default:
            break;
        }
    }

    return 0;
}

void do_benchmark()
{
    using namespace std::chrono;
    std::vector<MineThread*>* m_pvThreads;

    printer::inst()->print_msg(L0, "Running a 60 second benchmark...");

    uint8_t work[76] = { 0 };
    MineThread::MinerWork m_oMinerWork = MineThread::MinerWork("", work, sizeof(work), 0, 0, false, 0);
    m_pvThreads = MineThread::thread_starter(m_oMinerWork);

    uint64_t iStartStamp = time_point_cast<milliseconds>(high_resolution_clock::now()).time_since_epoch().count();

    std::this_thread::sleep_for(std::chrono::seconds(60));

    m_oMinerWork = MineThread::MinerWork();
    MineThread::switch_work(m_oMinerWork);

    double fTotalHps = 0.0;
    for (size_t i = 0; i < m_pvThreads->size(); ++i)
    {
        double fHps = (double)m_pvThreads->at(i)->m_iHashCount;
        fHps /= (m_pvThreads->at(i)->m_iTimestamp - iStartStamp) / 1000.0;

        printer::inst()->print_msg(L0, "Thread %u: %.1f H/S", i, fHps);
        fTotalHps += fHps;
    }

    printer::inst()->print_msg(L0, "Total: %.1f H/S", fTotalHps);
}
