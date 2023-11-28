class INTERVAL():
    def __init__(self, left, right):
        assert left<right
        self.left=left
        self.right=right
    
    def set_range(self, left, right):
        assert left<right
        self.left=left
        self.right=right
    
    def include(self, left, right):
        assert left<=right
        return self.left<=left and self.right>=right
    
    def interseced(self, left, right):
        assert left<=right
        return self.right>left and self.left<right
    
    def adjacent(self, left, right):
        assert left<=right
        return self.right>=left and self.left<=right
    
    def partof(self, left, right):
        assert left<=right
        if left<right:
            return left<=self.left and right>=self.right
        else:
            return False
    
    def equal(self, left, right):
        return self.left==left and self.right==self.right

class CHUNK():
    def __init__(self, chunk_addr, chunk_tail):
        self.mem_start=chunk_addr
        self.mem_end=chunk_tail
        self.next=None

# Require: there is no chunk(including fake interval) between chunk_addr and chunk_tail
def insert_chunk_list(chunk_list, chunk_addr, chunk_tail):
    chunk=chunk_list
    while chunk.next is not None and chunk.next.mem_end<=chunk_addr:
        chunk=chunk.next
    if chunk.mem_start==chunk.mem_end:
        chunk.mem_start=chunk_addr
        chunk.mem_end=chunk_tail
    elif chunk.next is None:
        chunk.next=CHUNK(chunk_addr, chunk_tail)
    elif chunk.next.mem_start==chunk.next.mem_end:
        chunk.next.mem_start=chunk_addr
        chunk.next.mem_end=chunk_tail
    else:
        fake_chunk=chunk_list
        while fake_chunk.next is not None:
            if fake_chunk.next.mem_start==fake_chunk.next.mem_end:
                fake_chunk.next.mem_start=chunk_addr
                fake_chunk.next.mem_end=chunk_tail
                break
            fake_chunk=fake_chunk.next
        if fake_chunk.next is not None:
            insert_chunk=fake_chunk.next
            fake_chunk.next=insert_chunk.next
        else:
            insert_chunk=CHUNK(chunk_addr, chunk_tail)
        insert_chunk.next=chunk.next
        chunk.next=insert_chunk
    return

def check_inactive_remove(chunk_list, chunk_addr, chunk_tail):
    interval=INTERVAL(chunk_addr, chunk_tail)
    while chunk_list is not None:
        assert chunk_list.next is None or chunk_list.mem_start<=chunk_list.next.mem_start
        assert chunk_list.next is None or chunk_list.next.mem_start==chunk_list.next.mem_end or chunk_list.mem_end<chunk_list.next.mem_start
        assert chunk_list.mem_end==chunk_list.mem_start or interval.interseced(chunk_list.mem_start, chunk_list.mem_end) is False
        chunk_list=chunk_list.next
    return

def check_inactive_insert(chunk_list, chunk_addr, chunk_tail):
    interval=INTERVAL(chunk_addr, chunk_tail)
    check_flag=False
    while chunk_list is not None:
        assert chunk_list.next is None or chunk_list.mem_start<=chunk_list.next.mem_start
        assert chunk_list.next is None or chunk_list.next.mem_start==chunk_list.next.mem_end or chunk_list.mem_end<chunk_list.next.mem_start
        if not check_flag and interval.partof(chunk_list.mem_start, chunk_list.mem_end):
            check_flag=True
        chunk_list=chunk_list.next
    assert check_flag
    return

def check_active_insert(chunk_list, chunk_addr, chunk_tail):
    interval=INTERVAL(chunk_addr, chunk_tail)
    check_flag=False
    while chunk_list is not None:
        assert chunk_list.next is None or chunk_list.mem_start<=chunk_list.next.mem_start
        assert chunk_list.next is None or chunk_list.next.mem_start==chunk_list.next.mem_end or chunk_list.mem_end<=chunk_list.next.mem_start
        if not check_flag and interval.equal(chunk_addr, chunk_tail):
            check_flag=True
        chunk_list=chunk_list.next
    assert check_flag
    return

def print_chunk_list_for_debug(chunk_list):
    s='{'
    while chunk_list is not None:
        s+='[%s, %s], '%(hex(chunk_list.mem_start), hex(chunk_list.mem_end))
        # assert(not (chunk_list.next is not None and chunk_list.next.mem_start<chunk_list.next.mem_end and chunk_list.mem_end>=chunk_list.next.mem_start))
        chunk_list=chunk_list.next
    if len(s)<2:
        s+='}'
    else:
        s=s[:-2]+'}'
    return s

class MemoryBlock():
    def __init__(self, SIZE_SZ):
        self.size_sz=SIZE_SZ
        self.range=INTERVAL(0, 1)
        self.active_chunk_list=None
        self.inactive_chunk_list=None
    
    def en_activable(self, chunk_addr: int, chunk_tail: int):
        self.range.set_range(chunk_addr, chunk_tail)
        #=======================================work on active chunks=======================================#
        active_chunk=self.active_chunk_list
        there_is_intersection=False
        while active_chunk is not None:
            if self.range.interseced(active_chunk.mem_start, active_chunk.mem_end):
                if not there_is_intersection:
                    active_chunk.mem_start=chunk_addr
                    active_chunk.mem_end=chunk_tail
                    # maybe destory mem_start ordered, measures need to be taken (3)
                    fake_chunk=self.active_chunk_list
                    while self.range.equal(fake_chunk.mem_start, fake_chunk.mem_end) is False:
                        while fake_chunk.next.mem_start==fake_chunk.next.mem_end:
                            saved_next_chunk=fake_chunk.next
                            fake_chunk.next=saved_next_chunk.next
                            del saved_next_chunk
                        fake_chunk=fake_chunk.next
                else:
                    active_chunk.mem_end=active_chunk.mem_start
                there_is_intersection=True
            active_chunk=active_chunk.next
        if not there_is_intersection:
            if self.active_chunk_list is None:
                self.active_chunk_list=CHUNK(chunk_addr, chunk_tail)
            elif chunk_tail<=self.active_chunk_list.mem_start:
                active_chunk=CHUNK(chunk_addr, chunk_tail)
                active_chunk.next=self.active_chunk_list
                self.active_chunk_list=active_chunk
            else:
                insert_chunk_list(self.active_chunk_list, chunk_addr, chunk_tail)
        #======================================work on inactive chunks======================================#
        inactive_chunk=self.inactive_chunk_list
        while inactive_chunk is not None:
            if self.range.include(inactive_chunk.mem_start, inactive_chunk.mem_end):
                inactive_chunk.mem_end=inactive_chunk.mem_start
            elif self.range.interseced(inactive_chunk.mem_start, inactive_chunk.mem_end):
                if self.range.partof(inactive_chunk.mem_start, inactive_chunk.mem_end):
                    if chunk_addr==inactive_chunk.mem_start:
                        if chunk_tail==inactive_chunk.mem_end:
                            inactive_chunk.mem_end=inactive_chunk.mem_start
                        else:
                            inactive_chunk.mem_start=chunk_tail
                            # maybe destory mem_start ordered, measures need to be taken (1)
                            while True:
                                fake_chunk=inactive_chunk.next
                                if fake_chunk is not None and fake_chunk.mem_start==fake_chunk.mem_end:
                                    inactive_chunk.next=fake_chunk.next
                                    del fake_chunk
                                else:
                                    break
                    else:
                        saved_mem_end=inactive_chunk.mem_end
                        inactive_chunk.mem_end=chunk_addr
                        chunk_addr=chunk_tail
                        if chunk_addr<saved_mem_end:
                            insert_chunk_list(self.inactive_chunk_list, chunk_tail, saved_mem_end)
                    break
                else:
                    assert inactive_chunk.mem_start<inactive_chunk.mem_end
                    if inactive_chunk.mem_start<chunk_addr:
                        inactive_chunk.mem_end=chunk_addr
                    elif inactive_chunk.mem_end>chunk_tail:
                        inactive_chunk.mem_start=chunk_tail
                        # maybe destory mem_start ordered, measures need to be taken (2)
                        while True:
                            fake_chunk=inactive_chunk.next
                            if fake_chunk is not None and fake_chunk.mem_start==fake_chunk.mem_end:
                                inactive_chunk.next=fake_chunk.next
                                del fake_chunk
                            else:
                                break
            inactive_chunk=inactive_chunk.next
        return
    
    def dis_activable(self, chunk_addr: int, chunk_tail: int):
        self.range.set_range(chunk_addr, chunk_tail)
        #=======================================work on active chunks=======================================#
        # for active chunks, work later
        #======================================work on inactive chunks======================================#
        inactive_chunk=self.inactive_chunk_list
        there_is_double_free=False
        insert_chunk=None
        while inactive_chunk is not None:
            if self.range.include(inactive_chunk.mem_start, inactive_chunk.mem_end):
                if not there_is_double_free and inactive_chunk.mem_start<inactive_chunk.mem_end:
                    there_is_double_free=True
                inactive_chunk.mem_end=inactive_chunk.mem_start
                if insert_chunk is None:
                    insert_chunk=inactive_chunk
            elif self.range.adjacent(inactive_chunk.mem_start, inactive_chunk.mem_end):
                if self.range.partof(inactive_chunk.mem_start, inactive_chunk.mem_end):
                    return True
                else:
                    if not there_is_double_free and self.range.interseced(inactive_chunk.mem_start, inactive_chunk.mem_end):
                        there_is_double_free=True
                    assert inactive_chunk.mem_start<inactive_chunk.mem_end
                    if inactive_chunk.mem_start<chunk_addr:
                        chunk_addr=inactive_chunk.mem_start
                    elif inactive_chunk.mem_end>chunk_tail:
                        chunk_tail=inactive_chunk.mem_end
                    inactive_chunk.mem_end=inactive_chunk.mem_start
                    if insert_chunk is None:
                        insert_chunk=inactive_chunk
            inactive_chunk=inactive_chunk.next
        if insert_chunk is not None:
            insert_chunk.mem_start=chunk_addr
            insert_chunk.mem_end=chunk_tail
            self.range.set_range(chunk_addr, chunk_tail)
            # maybe destory mem_start ordered, measures need to be taken (4)
            fake_chunk=self.inactive_chunk_list
            while self.range.equal(fake_chunk.mem_start, fake_chunk.mem_end) is False:
                while fake_chunk.next.mem_start==fake_chunk.next.mem_end:
                    saved_next_chunk=fake_chunk.next
                    fake_chunk.next=saved_next_chunk.next
                    del saved_next_chunk
                fake_chunk=fake_chunk.next
        else:
            if self.inactive_chunk_list is None:
                self.inactive_chunk_list=CHUNK(chunk_addr, chunk_tail)
            elif chunk_tail<=self.inactive_chunk_list.mem_start:
                inactive_chunk=CHUNK(chunk_addr, chunk_tail)
                inactive_chunk.next=self.inactive_chunk_list
                self.inactive_chunk_list=inactive_chunk
            else:
                insert_chunk_list(self.inactive_chunk_list, chunk_addr, chunk_tail)
        return there_is_double_free
    
    def check(self, addr: int, tail: int, SIZE_SZ: int):
        self.range.set_range(addr, tail)
        inactive_chunk=self.inactive_chunk_list
        inactive=False
        err_no=0 # Heap_overflow: 0x1  UAF: 0x2  Double_Free: 0x4  Stack_Overflow: 0x8
        while inactive_chunk is not None:
            if self.range.partof(inactive_chunk.mem_start, inactive_chunk.mem_end):
                err_no |= 0x1
                inactive=True
                break
            inactive_chunk=inactive_chunk.next
        if inactive is False:
            active_chunk=self.active_chunk_list
            while active_chunk is not None:
                if self.range.interseced(active_chunk.mem_start, active_chunk.mem_end+SIZE_SZ) and \
                not self.range.partof(active_chunk.mem_start+SIZE_SZ, active_chunk.mem_end):
                    err_no |= 0x1
                    break
                active_chunk=active_chunk.next
        return err_no
