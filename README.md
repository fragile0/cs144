# 浅谈CS144(计算机网络)

## 前言

		本人基础较差，在做这个lab之前只学过408的计算机网络，甚至谢希仁的计算机网络也没有读完。刚开学的时候一腔热血就打算冲cs144，如今过了三周，因为学校这边还有事情，断断续续的做完了前4个lab，其中lab2和lab3难度较大，过程中参考了一些代码，又加入了一些自己的想法，东拼西凑也算是苟完了这个实验的核心部分。尽管过程很艰辛，但看到所有测试样例通过的时候还是挺有成就感。总体上来说，这个实验设计还是优点大于缺点。
	
		先说说缺点，个人感觉整个lab2和lab3的文档写的比较啰嗦，很多东西重复了几遍。除此之外，也漏掉了一些细节，导致写代码的时候还要靠自己猜，如果实在猜不出只能参考别人的代码，最后错了还需要debug，这个需要耗费大量的时间，好在有其他前辈已经帮我们铺好了路，做之前也可以提前看看他们的代码避避坑，这也让省去了我大量debug时间。
	
		说完了缺点，再谈谈优点吧。总体来说整个实验设计还是十分合理的，一环套一环，而且也不会出现前面做的东西需要后面的知识的情况，大致看完文档之后就能对TCP整个过程有一个很深入的了解，如果能通过所有样例，对TCP的理解也会到达一个更高的高度，无论针对面试还是平时进行网络编程都有很大的帮助。



## 建议

* 不要急于求成，尽量把握每一个细节。

* 边做边复习，记录做的过程中遇到的困难。

* 具备一定的基础

  * Linux基本命令
  * 熟悉git的基本命令
  * 熟悉c语言
  * 懂得一些面向对象的知识
  * 熟练运用虚拟机

* 忍受孤独，投入较多的时间。

* 用git管理自己的代码，防止代码丢失。

* 适当参考前辈的代码，如kangyupl大佬(https://gitee.com/kangyupl)

* 考虑到这个课程网站在非教学时间是不上传文档的，有关文档可以在([CS 144: Introduction to Computer Networking (gitee.io)](https://kangyupl.gitee.io/cs144.github.io/))中获取。

  

## 实验

		实验部分主要谈谈如何配置环境，这个实验的需要环境还是挺多的。

### 1.环境配置

* 首先准备一个有Linux操作系统的主机，服务器或者虚拟机均可。

* 如果没有装Linux操作系统可以直接参考(https://www.cnblogs.com/ubuntuanzhuang/p/ubuntu2004.html)这个网页搭建Ubuntu64位实验环境即可。

* 打开Linux命令行，输入git clone https://github.com/cs144/sponge回车即可。如果这个网站没有开放也可以 git clone[cs144: lab of cs144 (gitee.com)](https://gitee.com/fragile_xia/cs144)，回退到起点就可以开始做了，后续需要的分支在我的gitee[cs144: lab of cs144 (gitee.com)](https://gitee.com/fragile_xia/cs144)中也可以找到，找到相关分支get merge origin+分支名即可。

* 如果对vim比较熟悉的同学可以直接使用vim写代码，比较方便。

* 如果跟我一样不熟悉vim的话，可以考虑用vscode，如果是用windows操作系统的同学可以使用

  vscode的Remote-SSH插件,如下图所示，装上之后就可以ssh到上自己的虚拟机开始做了。

![](C:\Users\jack\Desktop\readme\OMNABT~XUA0MZSYQCKO%7YH.png)

* 这个实验需要大量的调试过程，而这个程序调试起来并不是那么容易，具体流程我参考了kangyupl(https://www.cnblogs.com/kangyupl/p/stanford_cs144_labs.html)的调试方法论得到。

* 配置完以上环境，就可以愉快的开始做实验啦！

* 做的过程中有几个常用的文件

  * build文件 

    存储构建项目的相关文件，使用以下命令即可完成每个lab的检测

    ```
    cd build
    make
    make check_labx
    ```

  * libsponge文件

    包含几乎所有实验过程中需要完成的.c和.h文件。

  * tests文件

    包含实验中所有测试样例源代码，如果某个样例failed, 可以直接在这里面找到源代码进行打断点调试， 也可以找到测试数据。

  * writesup文件

    存储对每个实验过程的记录，可以把每个实验中需要的困难写到lab.md文件中。

### 2.lab0 实现一个缓冲区

		lab0需要实现了两个函数，一个是webget.c，实现的功能主要是给定目标主机和一个路径，获取浏览器中的返回的信息，模拟了我们访问网页的过程，需要我们阅读官网上的部分源文件。这部分大家的实现方式都差不多，主要代码如下：

```c++
void get_URL(const string &host, const string &path) {
    TCPSocket socket;
    socket.connect(Address(host, "http"));
    string info =   "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + host + "\r\n" +
                    "Connection: close\r\n\r\n";
    socket.write(info); 
    socket.shutdown(SHUT_WR); 
    for (auto recvd = socket.read(); !socket.eof(); recvd = socket.read())
        cout << recvd;
    socket.close();	
    cerr << "Function called: get_URL(" << host << ", " << path << ").\n";
    cerr << "Warning: get_URL() has not been implemented yet.\n";
}

```

		另一个函数是byte_stream.cc, 这个十分函数重要，为后面的滑动窗口埋下了伏笔。主要实现如下：

```c++
size_t ByteStream::write(const string &data) {
    size_t  len_write = min(data.size(), remaining_capacity());
    for (size_t i = 0; i < len_write; i++)
	buff.push_back(data[i]);
    _bytes_written += len_write;
    return len_write;
}

string ByteStream::peek_output(const size_t len) const {
    size_t len_peek = min(buffer_size(), len); 
    return string().assign(buff.begin(), buff.begin() + len_peek);
}

void ByteStream::pop_output(const size_t len) { 
     size_t len_pop = min(buffer_size(), len);
     for (size_t i = 0; i < len_pop; i++)
	buff.pop_front();
     _bytes_read += len_pop;
}

std::string ByteStream::read(const size_t len) {
    size_t len_read = min(buffer_size(), len);
    string string_read = "";
    for (size_t i = 0; i < len_read; i++) {
	string_read.push_back(buff.front());
	buff.pop_front();
    }
    _bytes_read += len_read;
    return string_read;
}

void ByteStream::end_input() {
    _end_input = true;
}

bool ByteStream::input_ended() const { 
    return _end_input; 
}

size_t ByteStream::buffer_size() const { 
    return buff.size(); 
}

bool ByteStream::buffer_empty() const { 
    return buff.empty(); 
}

bool ByteStream::eof() const { 
    return _end_input && buffer_empty(); 
}

size_t ByteStream::bytes_written() const { 
    return _bytes_written; 
}

size_t ByteStream::bytes_read() const { 
    return _bytes_read; 
}

size_t ByteStream::remaining_capacity() const { 
    return _capacity - buff.size(); 
}
```

### 3.lab1 实现一个字节流重组器

```c++
#include "stream_reassembler.hh"

using namespace std;

StreamReassembler::StreamReassembler(const size_t capacity) : _output(capacity), _capacity(capacity) {
}

void StreamReassembler::push_substring(const string &data, const size_t index, const bool eof) {
    // 队头 和 队尾
    size_t hh = index, tt = index + data.size();
    bool flag = true;
    // 队尾出界 + 更新队尾
    if (_head + _output.remaining_capacity() < tt) { 
        flag = false;
        tt = _head + _output.remaining_capacity();
    } 
    // 更新队头
    if (hh < _head)
        hh = _head;
    // 从队头到队尾遍历一遍,填充所有空白的节点
    for (size_t i = hh; i < tt; i++) {
        if (_hash.count(i)) continue;
        _hash.insert({i, data[i - index]});
        _unreassembled_bytes++;
    }
    // 从head开始遍历，把所有可以遍历的结点遍历一遍
    string str = "";
    for (size_t i = _head; _hash.count(i); i++) {
        str.push_back(_hash[i]);
        _hash.erase(i);
        _head++;
        _unreassembled_bytes--;
    } 
   
    // 队尾不溢出同时存在结束标志
    if (flag && eof)
	_eof = true;
    // 前面已经出现了eof并且所有字符已经处理完 	
    if (_eof && empty())
        _output.end_input();
}

size_t StreamReassembler::unassembled_bytes() const { 
    return _unreassembled_bytes;
}

bool StreamReassembler::empty() const { 
    return unassembled_bytes() == 0;
 }
```

### 4.lab2 TCP接收器的实现

**wrapping_integers.cc**

```c++
#include "wrapping_integers.hh"

using namespace std;

WrappingInt32 wrap(uint64_t n, WrappingInt32 isn) {
    return WrappingInt32(static_cast<uint32_t>(n) + isn.raw_value()); 
}

uint64_t unwrap(WrappingInt32 n, WrappingInt32 isn, uint64_t checkpoint) {
    uint64_t mask = 0xffffffff00000000, offset = 1ul << 32;
    uint32_t _abso_seq = n.raw_value() - isn.raw_value(); 
    uint64_t t = (checkpoint & mask) + _abso_seq;
    uint64_t mi = t > checkpoint ? t - checkpoint : checkpoint - t;
    uint64_t ans = t;
    if (t < mask && t + offset - checkpoint < mi)
        mi = t + offset - checkpoint, ans = t + offset;
    if (t >= offset && checkpoint - (t - offset) < mi)
        mi = checkpoint - (t - offset), ans = t - offset;
    return ans;
}
```

**TCPReceiver.hh**

```c++
#ifndef SPONGE_LIBSPONGE_TCP_RECEIVER_HH
#define SPONGE_LIBSPONGE_TCP_RECEIVER_HH

#include "byte_stream.hh"
#include "stream_reassembler.hh"
#include "tcp_segment.hh"
#include "wrapping_integers.hh"

#include <optional>

class TCPReceiver {
    StreamReassembler _reassembler;
    size_t _head = 0;   // 64bit
    size_t _isn = 0;  // 64bit
    size_t _capacity;
    bool _syn = false;
    bool _fin = false;
  public:
    //! \brief Construct a TCP receiver
    //!
    //! \param capacity the maximum number of bytes that the receiver will
    //!                 store in its buffers at any give time.
    TCPReceiver(const size_t capacity) : _reassembler(capacity), _capacity(capacity) {}

    //! \name Accessors to provide feedback to the remote TCPSender
    //!@{

    //! \brief The ackno that should be sent to the peer
    //! \returns empty if no SYN has been received
    //!
    //! This is the beginning of the receiver's window, or in other words, the sequence number
    //! of the first byte in the stream that the receiver hasn't received.
    std::optional<WrappingInt32> ackno() const;

    //! \brief The window size that should be sent to the peer
    //!
    //! Operationally: the capacity minus the number of bytes that the
    //! TCPReceiver is holding in its byte stream (those that have been
    //! reassembled, but not consumed).
    //!
    //! Formally: the difference between (a) the sequence number of
    //! the first byte that falls after the window (and will not be
    //! accepted by the receiver) and (b) the sequence number of the
    //! beginning of the window (the ackno).
    size_t window_size() const;
    //!@}

    //! \brief number of bytes stored but not yet reassembled
    size_t unassembled_bytes() const { return _reassembler.unassembled_bytes(); }

    //! \brief handle an inbound segment
    //! \returns `true` if any part of the segment was inside the window
    bool segment_received(const TCPSegment &seg);

    //! \name "Output" interface for the reader
    //!@{
    ByteStream &stream_out() { return _reassembler.stream_out(); }
    const ByteStream &stream_out() const { return _reassembler.stream_out(); }
    //!@}
};

#endif  // SPONGE_LIBSPONGE_TCP_RECEIVER_HH
```

**TCP_Receiver.hh**

```c++
#include "tcp_receiver.hh"

using namespace std;

// 1.SYN with data
// 2.FIN with data
// 3.SYN with FIN 
// 4.SYN with FIN with data
// 5.data 
// 6.SYN 
// 7.FIN
// 8.0

bool TCPReceiver::segment_received(const TCPSegment &seg) {
    // 计算出绝对地址 和 长度 
    size_t abs_seq = 0;
    abs_seq = unwrap(WrappingInt32(seg.header().seqno.raw_value()), WrappingInt32(_isn), abs_seq);
    size_t len = seg.length_in_sequence_space();
    // 是否存在SYN 
    if (seg.header().syn) {
        if (_syn)
            return false;
        _syn = true;
        _head++, abs_seq++; 
        _isn = seg.header().seqno.raw_value();
        // 6. SYN
        if (--len == 0)
            return true;
    } else if (!_syn) {
        return false;
    }
    // 是否存在FIN 
    if (seg.header().fin) {
        if (_fin)
            return false;
        _fin = true;
      // 8. 0
    } else if (seg.length_in_sequence_space() == 0) {
        return _head == abs_seq;
       // 5. data
    } else if (!seg.header().syn){
        if (abs_seq >= _head + window_size() || abs_seq + len <= _head)
            return false;
    }
    // 剩下的帧全部接收
    _reassembler.push_substring(seg.payload().copy(), abs_seq - 1, seg.header().fin);
    // 转化成绝对坐标
    _head = _reassembler.get_head_index() + 1;
    if (_reassembler.stream_out().input_ended())  _head++;
    return true;
}
  
optional<WrappingInt32> TCPReceiver::ackno() const {
     if (_head > 0)
        return WrappingInt32(wrap(_head, WrappingInt32(_isn)));
    else
        return std::nullopt;
}

size_t TCPReceiver::window_size() const {
    return _capacity -_reassembler.stream_out().buffer_size();
}
```

### 5.lab3  TCP发送器的实现

**TCPSender.hh**

```c++
#ifndef SPONGE_LIBSPONGE_TCP_SENDER_HH
#define SPONGE_LIBSPONGE_TCP_SENDER_HH

#include "byte_stream.hh"
#include "tcp_config.hh"
#include "tcp_segment.hh"
#include "wrapping_integers.hh"

#include <functional>
#include <queue>

class TCPSender {
  private:
    WrappingInt32 _isn;
    uint64_t _initial_retransmission_timeout;
    ByteStream _stream;  
    uint64_t _retransmission_timeout;
    
    // 存储发出的报文段
    std::queue<TCPSegment> _segments_out{};
    std::queue<TCPSegment> _segments_wait{};
   
    // 重传时间相关参数 
    uint64_t _cur_timeout = 0;
    size_t _consecutive_retransmission = 0;

    // 时钟相关参数
    bool _fin_flag = false;
    bool _syn_flag = false;
    bool _is_timer_running = false;
    bool _zero_flag = false;

    
    // 滑动窗口相关参数
    uint64_t _ack_seq = 0;
    uint64_t _next_seqno = 0;
    uint64_t _win_size = 1;
  public:
    TCPSender(const size_t capacity = TCPConfig::DEFAULT_CAPACITY,
              const uint16_t retx_timeout = TCPConfig::TIMEOUT_DFLT,
              const std::optional<WrappingInt32> fixed_isn = {});

    ByteStream &stream_in() { return _stream; }

    const ByteStream &stream_in() const { return _stream; }

    bool ack_received(const WrappingInt32 ackno, const uint16_t window_size);

    void send_empty_segment();

    void fill_window();

    void tick(const size_t ms_since_last_tick);

    size_t bytes_in_flight() const;

    unsigned int consecutive_retransmissions() const;

    std::queue<TCPSegment> &segments_out() { return _segments_out; }

    uint64_t next_seqno_absolute() const { return _next_seqno; }

    WrappingInt32 next_seqno() const { return wrap(_next_seqno, _isn); }
};

#endif  // SPONGE_LIBSPONGE_TCP_SENDER_HH

```

**TCPSender.cc**

```c++
#include "tcp_sender.hh"

#include "tcp_config.hh"

#include <random>

using namespace std;

TCPSender::TCPSender(const size_t capacity, const uint16_t retx_timeout, const std::optional<WrappingInt32> fixed_isn)
    : _isn(fixed_isn.value_or(WrappingInt32{random_device()()}))
    , _initial_retransmission_timeout{retx_timeout}
    , _stream(capacity) 
    , _retransmission_timeout(retx_timeout) {}

uint64_t TCPSender::bytes_in_flight() const { return _next_seqno - _ack_seq; }

void TCPSender::fill_window() { 
    if (_win_size == 0 || _fin_flag)   return;
    TCPSegment seg;
    if (!_syn_flag) {
        // 发一个SYN帧
        _syn_flag = 1;
        seg.header().syn = 1;
        seg.header().seqno = next_seqno();
        _next_seqno++;
        _win_size--;
        _segments_out.push(seg);
        _segments_wait.push(seg);
    } else if (stream_in().eof()) {
        // 发一个FIN帧
        _fin_flag = 1;
        seg.header().fin = 1;
        seg.header().seqno = next_seqno();
        _next_seqno++;
        _win_size--;
        _segments_out.push(seg);
        _segments_wait.push(seg);
    } else {
        // 发一个普通帧 但要填满window
        // 如果字节流非空以及window还有空间，就不断填充
        while (_win_size > 0 && !stream_in().buffer_empty()) {
            seg.header().seqno = next_seqno();
            // 取窗口大小 以及 字节流的大小 以及 最大报文长度的最小值
            size_t send_len = min(_win_size, min(TCPConfig::MAX_PAYLOAD_SIZE, stream_in().buffer_size()));
            seg.payload()= stream_in().read(send_len);
            if (seg.length_in_sequence_space() < _win_size && stream_in().eof()) {
                _fin_flag = true;
                seg.header().fin = true;
            }
            _next_seqno += seg.length_in_sequence_space();
            _win_size -= seg.length_in_sequence_space();
            _segments_out.push(seg);
            _segments_wait.push(seg);
        }
    }
    // 开启计时器
    if (!_is_timer_running) {
        _is_timer_running = true;
        _cur_timeout = 0;
    }
}

bool TCPSender::ack_received(const WrappingInt32 ackno, const uint16_t window_size) {
    // ack的绝对编号 ack是期望收到的第一个帧
    uint64_t ack_abs = unwrap(ackno, _isn, _next_seqno);
    // ack跳出界限
    if (ack_abs > _next_seqno) {
        return false;
    }
    _win_size = window_size;
    if (ack_abs <= _ack_seq)
        return true;
    // 接收这个ack
    // 设置窗口 设置重传时间 重传次数归零

    _consecutive_retransmission = 0;
    _retransmission_timeout = _initial_retransmission_timeout;
    // 弹出队列中编号小于ackno的帧
    while (!_segments_wait.empty()) {
        TCPSegment seg = _segments_wait.front();
        // 存储seg的末端
        uint64_t seq = seg.length_in_sequence_space() + unwrap(seg.header().seqno, _isn, _next_seqno);
        if (seq <= ack_abs) {
            _ack_seq = seq;
            _segments_wait.pop();
        } else {
            break;
        }
    }
    if (!_segments_wait.empty()) {
        _cur_timeout = 0;
        _is_timer_running = true;
    } else {
        _is_timer_running = false;
    }
    // 待收到的数据已经大于窗口，则不能再发了
    if (bytes_in_flight() > window_size) {
        _win_size = 0;
        _zero_flag = true;
        return true;
    }
    if (_win_size == 0) {
        _win_size = 1;
        _zero_flag = true;
    } else {
        _zero_flag = false;
    }
    fill_window();
    return true;
}

void TCPSender::tick(const size_t ms_since_last_tick) { 
    _cur_timeout += ms_since_last_tick;
    // 如果当前时间已经大于了重传时间，此时重发丢失的数据报文
    if (_cur_timeout >= _retransmission_timeout && !_segments_wait.empty()) {
        _segments_out.push(_segments_wait.front());
        _cur_timeout = 0;
        if (!_zero_flag) {
            _retransmission_timeout *= 2;
            _consecutive_retransmission++;
        }
    }
    // 如果等待队列为空 计时器关闭
    if (_segments_wait.empty()) {
        _is_timer_running = false;
    }
 }

unsigned int TCPSender::consecutive_retransmissions() const { 
    return _consecutive_retransmission; 
}

void TCPSender::send_empty_segment() {
    TCPSegment seg;
    seg.header().seqno = next_seqno();
    _segments_out.push(seg);
}
```

### 6.TCP连接器 - 状态机



