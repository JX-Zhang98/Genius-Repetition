#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

from redis import Redis
from nearpy.storage import RedisStorage
from nearpy.hashes import RandomBinaryProjections
from nearpy.filters import NearestFilter
from nearpy.distances import CosineDistance
from nearpy import Engine
import numpy as np
import multiprocessing as mp
import json

class DB:

    def __init__(self, feature_size=16, nearest_neighbours=1000):
        self.feature_size = feature_size
        self.nn = nearest_neighbours
        self.engine = None
        self.load_hashmap()

    def load_hashmap(self):
        # Create redis storage adapter
        # need to start redis service
        redis_object = Redis(host='localhost', port=6379, db=14)
        redis_storage = RedisStorage(redis_object)
        try:
            config = redis_storage.load_hash_configuration('test')
            lshash = RandomBinaryProjections(None, None)
            lshash.apply_config(config)

        except:
            # Config is not existing, create hash from scratch, with 10 projections
            lshash = RandomBinaryProjections('test', 10)

        nearest = NearestFilter(self.nn)
        # self.engine = Engine(feature_size, lshashes=[], vector_filters=[])
        self.engine = Engine(self.feature_size,
                             lshashes=[lshash],
                             vector_filters=[nearest],
                             storage=redis_storage,
                             distance=CosineDistance())

        # Do some stuff like indexing or querying with the engine...

        # Finally store hash configuration in redis for later use
        redis_storage.store_hash_configuration(lshash)

    def query(self, fvector):
        query = np.asarray(fvector)

        # get nn nearest neighbours
        # a list of tuple (data, name, distance)
        N = self.engine.neighbours(query)
        return N

    def append_to_DB(self, fvector, name=""):
        if fvector is None:
            return
        self.engine.store_vector(np.asarray(fvector), name)


if __name__ == "__main__":
    db = DB(feature_size=16, nearest_neighbours=2958)
    f = open("../fVec.json", "r")
    a = json.load(f)
    for key, value in a.items():
        db.append_to_DB(value, key)

