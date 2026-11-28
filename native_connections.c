/* Read-only libproc socket snapshots for an explicitly selected PID set.
 * Darwin layouts come directly from the build SDK, never duplicated in Python.
 * No process enumeration, signals, socket traffic, names, paths or logging.
 */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#define RG_ABI 1u
#define RG_MAX_PIDS 128u
#define RG_MAX_ROWS 4096u
#define RG_MAX_FDS 16384u
#define RG_MAX_TOTAL_FDS 65536u
#define RG_UNKNOWN 1
#define RG_LIMIT 2
#define RG_UNSTABLE 3
#define RG_SIP 1u
#define RG_SPORT 2u
#define RG_DIP 4u
#define RG_DPORT 8u

struct rg_socket_row {
    int32_t pid;
    uint32_t network;
    uint32_t family;
    uint32_t flags;
    uint32_t source_port;
    uint32_t destination_port;
    uint32_t tcp_state;
    uint32_t reserved;
    uint8_t source_addr[16];
    uint8_t destination_addr[16];
};

_Static_assert(sizeof(struct rg_socket_row) == 64, "private socket ABI");
_Static_assert(sizeof(struct proc_fdinfo) == 8, "SDK fd-list ABI");
_Static_assert(offsetof(struct tcp_sockinfo, tcpsi_ini) == 0, "SDK TCP/INET prefix");
_Static_assert(sizeof(((struct in_sockinfo *)0)->insi_faddr) == 16, "SDK INET union");

/* Fixed, non-private SDK/bridge layout metadata for runtime ABI validation. */
int rg_native_socket_abi(uint32_t *values, uint32_t count) {
    if (values == NULL || count != 10) return RG_UNKNOWN;
    values[0] = RG_ABI;
    values[1] = (uint32_t)sizeof(struct rg_socket_row);
    values[2] = (uint32_t)sizeof(struct proc_bsdinfo);
    values[3] = (uint32_t)sizeof(struct proc_fdinfo);
    values[4] = (uint32_t)sizeof(struct socket_fdinfo);
    values[5] = (uint32_t)offsetof(struct socket_fdinfo, psi);
    values[6] = (uint32_t)offsetof(struct socket_info, soi_proto);
    values[7] = (uint32_t)sizeof(struct in_sockinfo);
    values[8] = (uint32_t)sizeof(struct tcp_sockinfo);
    values[9] = (uint32_t)offsetof(struct in_sockinfo, insi_faddr);
    return 0;
}

static int valid_owner(int32_t pid, const struct proc_bsdinfo *info, uid_t uid) {
    return info->pbi_pid == (uint32_t)pid && info->pbi_uid == uid &&
           info->pbi_ruid == uid && info->pbi_svuid == uid &&
           !(info->pbi_flags & (PROC_FLAG_SYSTEM | PROC_FLAG_INEXIT | PROC_FLAG_PSUGID));
}

static int owner(int32_t pid, struct proc_bsdinfo *info) {
    memset(info, 0, sizeof(*info));
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, (int)sizeof(*info));
    if (size != (int)sizeof(*info) || !valid_owner(pid, info, getuid())) return RG_UNKNOWN;
    return 0;
}

static int same_owner(const struct proc_bsdinfo *a, const struct proc_bsdinfo *b) {
    return a->pbi_pid == b->pbi_pid && a->pbi_uid == b->pbi_uid &&
           a->pbi_ruid == b->pbi_ruid && a->pbi_svuid == b->pbi_svuid &&
           a->pbi_start_tvsec == b->pbi_start_tvsec && a->pbi_start_tvusec == b->pbi_start_tvusec;
}

static int fd_order(const void *left, const void *right) {
    const struct proc_fdinfo *a = left, *b = right;
    if (a->proc_fd != b->proc_fd) return a->proc_fd < b->proc_fd ? -1 : 1;
    return a->proc_fdtype < b->proc_fdtype ? -1 : a->proc_fdtype != b->proc_fdtype;
}

static int socket_fds(int32_t pid, struct proc_fdinfo **out, uint32_t *count, uint32_t *total) {
    *out = NULL;
    *count = 0;
    errno = 0;
    int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed <= 0 || needed % (int)sizeof(struct proc_fdinfo)) return RG_UNKNOWN;
    uint32_t slots = (uint32_t)needed / (uint32_t)sizeof(struct proc_fdinfo);
    if (slots > RG_MAX_FDS - 64u) return RG_LIMIT;
    slots += 64u;
    size_t bytes = (size_t)slots * sizeof(struct proc_fdinfo);
    if (bytes > INT_MAX) return RG_LIMIT;
    struct proc_fdinfo *fds = calloc(slots, sizeof(*fds));
    if (fds == NULL) return RG_UNKNOWN;
    int received = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)bytes);
    if (received <= 0 || received >= (int)bytes || received % (int)sizeof(*fds)) {
        free(fds);
        return RG_UNSTABLE;
    }
    uint32_t rows = (uint32_t)received / (uint32_t)sizeof(*fds);
    if (rows > RG_MAX_TOTAL_FDS - *total) {
        free(fds);
        return RG_LIMIT;
    }
    *total += rows;
    qsort(fds, rows, sizeof(*fds), fd_order);
    uint32_t kept = 0;
    for (uint32_t index = 0; index < rows; index++) {
        if (fds[index].proc_fd < 0 || (index && fds[index].proc_fd == fds[index - 1].proc_fd)) {
            free(fds);
            return RG_UNSTABLE;
        }
        if (fds[index].proc_fdtype == PROX_FDTYPE_SOCKET) fds[kept++] = fds[index];
    }
    *out = fds;
    *count = kept;
    return 0;
}

/* Return one for a retained socket, zero for an explicitly out-of-scope socket,
 * negative for an unrecognized/unsafe snapshot. LISTEN is the only TCP state
 * intentionally excluded; pending and closing sockets remain observations.
 */
static int decode(const struct socket_fdinfo *input, int32_t pid, struct rg_socket_row *row) {
    const struct socket_info *socket = &input->psi;
    if (socket->soi_family != AF_INET && socket->soi_family != AF_INET6) return 0;
    const struct in_sockinfo *inet;
    uint32_t state = UINT32_MAX;
    if (socket->soi_protocol == IPPROTO_TCP && socket->soi_type == SOCK_STREAM) {
        if (socket->soi_kind != SOCKINFO_TCP) return -1;
        int tcp_state = socket->soi_proto.pri_tcp.tcpsi_state;
        if (tcp_state < TSI_S_CLOSED || tcp_state > TSI_S_TIME_WAIT) return -1;
        if (tcp_state == TSI_S_LISTEN) return 0;
        state = (uint32_t)tcp_state;
        inet = &socket->soi_proto.pri_tcp.tcpsi_ini;
    } else if (socket->soi_protocol == IPPROTO_UDP && socket->soi_type == SOCK_DGRAM) {
        if (socket->soi_kind != SOCKINFO_IN) return -1;
        inet = &socket->soi_proto.pri_in;
    } else return 0;
    if ((inet->insi_vflag & ~(INI_IPV4 | INI_IPV6)) ||
        !(inet->insi_vflag & (INI_IPV4 | INI_IPV6)) ||
        inet->insi_lport < 0 || inet->insi_lport > UINT16_MAX ||
        inet->insi_fport < 0 || inet->insi_fport > UINT16_MAX) return -1;
    int ipv4 = socket->soi_family == AF_INET ||
               ((inet->insi_vflag & INI_IPV4) && !(inet->insi_vflag & INI_IPV6));
    if (socket->soi_family == AF_INET && !(inet->insi_vflag & INI_IPV4)) return -1;
    if (!ipv4 && !(inet->insi_vflag & INI_IPV6)) return -1;
    memset(row, 0, sizeof(*row));
    row->pid = pid;
    row->network = (uint32_t)socket->soi_protocol;
    row->family = ipv4 ? 4u : 6u;
    row->tcp_state = state;
    row->source_port = ntohs((uint16_t)inet->insi_lport);
    row->destination_port = ntohs((uint16_t)inet->insi_fport);
    const void *source = ipv4 ? (const void *)&inet->insi_laddr.ina_46.i46a_addr4 :
                               (const void *)&inet->insi_laddr.ina_6;
    const void *destination = ipv4 ? (const void *)&inet->insi_faddr.ina_46.i46a_addr4 :
                                    (const void *)&inet->insi_faddr.ina_6;
    size_t length = ipv4 ? 4u : 16u;
    memcpy(row->source_addr, source, length);
    memcpy(row->destination_addr, destination, length);
    row->flags = RG_SIP;
    if (row->source_port) row->flags |= RG_SPORT;
    uint8_t any = 0;
    for (size_t index = 0; index < length; index++) any |= row->destination_addr[index];
    if (any) row->flags |= RG_DIP;
    if (row->destination_port) row->flags |= RG_DPORT;
    return 1;
}

static int same_socket(const struct socket_fdinfo *a, const struct socket_fdinfo *b, int32_t pid) {
    if (a->psi.soi_so != b->psi.soi_so || a->psi.soi_pcb != b->psi.soi_pcb ||
        a->psi.soi_family != b->psi.soi_family || a->psi.soi_protocol != b->psi.soi_protocol ||
        a->psi.soi_type != b->psi.soi_type || a->psi.soi_kind != b->psi.soi_kind) return 0;
    struct rg_socket_row left, right;
    int l = decode(a, pid, &left), r = decode(b, pid, &right);
    if (l != r || l < 0) return 0;
    if (!l) return 1;
    const struct in_sockinfo *ia = a->psi.soi_kind == SOCKINFO_TCP ? &a->psi.soi_proto.pri_tcp.tcpsi_ini : &a->psi.soi_proto.pri_in;
    const struct in_sockinfo *ib = b->psi.soi_kind == SOCKINFO_TCP ? &b->psi.soi_proto.pri_tcp.tcpsi_ini : &b->psi.soi_proto.pri_in;
    if (ia->insi_gencnt != ib->insi_gencnt) return 0;
    left.tcp_state = right.tcp_state; /* handshake/closing state changes preserve endpoints */
    return memcmp(&left, &right, sizeof(left)) == 0;
}

int rg_read_owned_sockets(const int32_t *pids, uint32_t npids, struct rg_socket_row *rows,
                         uint32_t capacity, uint32_t allow_self, uint32_t *out_count) {
    if (out_count == NULL) return RG_UNKNOWN;
    *out_count = 0;
    if (pids == NULL || rows == NULL || !npids || npids > RG_MAX_PIDS ||
        !capacity || capacity > RG_MAX_ROWS || allow_self > 1) return RG_UNKNOWN;
    for (uint32_t index = 0; index < npids; index++) {
        if (pids[index] <= 1 || (!allow_self && pids[index] == getpid())) return RG_UNKNOWN;
        for (uint32_t earlier = 0; earlier < index; earlier++)
            if (pids[index] == pids[earlier]) return RG_UNKNOWN;
    }
    uint32_t count = 0, total_fds = 0;
    for (uint32_t index = 0; index < npids; index++) {
        int32_t pid = pids[index];
        struct proc_bsdinfo initial;
        if (owner(pid, &initial)) return RG_UNKNOWN;
        uint32_t first_count = count;
        int completed = 0;
        for (unsigned attempt = 0; attempt < 2 && !completed; attempt++) {
            struct proc_fdinfo *before = NULL, *after = NULL;
            uint32_t before_count = 0, after_count = 0;
            int result = socket_fds(pid, &before, &before_count, &total_fds);
            count = first_count;
            if (result) return result;
            for (uint32_t fd = 0; fd < before_count; fd++) {
                struct socket_fdinfo a, b;
                memset(&a, 0, sizeof(a));
                memset(&b, 0, sizeof(b));
                int n = proc_pidfdinfo(pid, before[fd].proc_fd, PROC_PIDFDSOCKETINFO, &a, (int)sizeof(a));
                int m = proc_pidfdinfo(pid, before[fd].proc_fd, PROC_PIDFDSOCKETINFO, &b, (int)sizeof(b));
                if (n != (int)sizeof(a) || m != (int)sizeof(b) || !same_socket(&a, &b, pid)) {
                    result = RG_UNSTABLE;
                    break;
                }
                struct rg_socket_row row;
                int retained = decode(&b, pid, &row);
                if (retained < 0) { result = RG_UNKNOWN; break; }
                if (retained) {
                    if (count >= capacity) { result = RG_LIMIT; break; }
                    rows[count++] = row;
                }
            }
            if (!result) {
                result = socket_fds(pid, &after, &after_count, &total_fds);
                if (!result && (before_count != after_count ||
                    memcmp(before, after, (size_t)before_count * sizeof(*before)))) result = RG_UNSTABLE;
            }
            free(before);
            free(after);
            struct proc_bsdinfo final;
            if (owner(pid, &final) || !same_owner(&initial, &final)) return RG_UNKNOWN;
            if (result && result != RG_UNSTABLE) return result;
            if (!result) completed = 1;
        }
        if (!completed) return RG_UNSTABLE;
    }
    *out_count = count;
    return 0;
}

#ifdef RG_NATIVE_TESTING
/* SDK-native synthetic structures, not process reads or traffic. */
int rg_native_owner_fixture(uint32_t scenario) {
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    info.pbi_pid = 20;
    info.pbi_uid = info.pbi_ruid = info.pbi_svuid = getuid();
    if (scenario == 1) info.pbi_pid++;
    if (scenario == 2) info.pbi_uid++;
    if (scenario == 3) info.pbi_ruid++;
    if (scenario == 4) info.pbi_svuid++;
    if (scenario == 5) info.pbi_flags = PROC_FLAG_SYSTEM;
    if (scenario == 6) info.pbi_flags = PROC_FLAG_INEXIT;
    if (scenario == 7) info.pbi_flags = PROC_FLAG_PSUGID;
    return valid_owner(20, &info, getuid()) ? 0 : RG_UNKNOWN;
}

int rg_native_decode_fixture(uint32_t scenario, uint32_t state, struct rg_socket_row *row) {
    struct socket_fdinfo input;
    memset(&input, 0, sizeof(input));
    input.psi.soi_family = scenario == 3 || scenario == 4 ? AF_INET6 : AF_INET;
    input.psi.soi_type = scenario == 1 || scenario == 2 || scenario == 4 ? SOCK_DGRAM : SOCK_STREAM;
    input.psi.soi_protocol = input.psi.soi_type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP;
    input.psi.soi_kind = input.psi.soi_protocol == IPPROTO_UDP ? SOCKINFO_IN : SOCKINFO_TCP;
    struct in_sockinfo *inet = input.psi.soi_kind == SOCKINFO_TCP ?
        &input.psi.soi_proto.pri_tcp.tcpsi_ini : &input.psi.soi_proto.pri_in;
    inet->insi_vflag = input.psi.soi_family == AF_INET ? INI_IPV4 : INI_IPV6;
    inet->insi_lport = htons(12345);
    inet->insi_fport = scenario == 2 ? 0 : htons(23456);
    if (input.psi.soi_family == AF_INET) {
        inet_pton(AF_INET, "127.0.0.1", &inet->insi_laddr.ina_46.i46a_addr4);
        if (scenario != 2) inet_pton(AF_INET, "127.0.0.1", &inet->insi_faddr.ina_46.i46a_addr4);
    } else {
        inet_pton(AF_INET6, "::1", &inet->insi_laddr.ina_6);
        inet_pton(AF_INET6, "::1", &inet->insi_faddr.ina_6);
    }
    if (input.psi.soi_kind == SOCKINFO_TCP) input.psi.soi_proto.pri_tcp.tcpsi_state = (int)state;
    if (scenario == 5) input.psi.soi_family = AF_UNIX;
    if (scenario == 6) inet->insi_vflag = 0x80;
    if (scenario == 7) inet->insi_lport = 65536;
    if (scenario == 8) input.psi.soi_kind = SOCKINFO_GENERIC;
    return decode(&input, 20, row);
}
#endif
