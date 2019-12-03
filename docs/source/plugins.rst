##################
Extending nfstream
##################

nfstream is designed to be flexible and machine learning oriented. In the following section, we depict the use of NFPlugin
in both cases.

.. code-block:: python

    from nfstream import NFPlugin

    class my_awesome_plugin(NFPlugin):
        def on_update(self, obs, entry):
            if obs.length >= 666:
                entry.my_awesome_plugin += 1


   streamer_awesome = NFStreamer(source='devil.pcap', plugins=[my_awesome_plugin()])
   for flow in streamer_awesome:
      print(flow.my_awesome_plugin) # now you will see your dynamically created metric in generated flows

*******************
NFPlugin parameters
*******************
* ``name`` [default= ``class name`` ]

  - Plugin name. Must be unique as it's dynamically created as a flow attribute.

* ``volatile`` [default=``False``]

  - Volatile plugin is available only when flow is processed. At flow expiration level, plugin is automatically removed (will not appear as flow attribute).

* ``user_data`` [default=``None``]

  - user_data passed to the plugin. Example: external module, pickled sklearn model, etc.

****************
NFPlugin methods
****************
* ``on_init(self, obs)`` [default=``return 0``]

  - Method called at entry creation). When aggregating packets into flows, this method is called on ``NFFlow`` object creation based on first ``NFPacket`` object belonging to it.

* ``on_update(self, obs, entry)`` [default=``pass``]

  - Method called to update each entry with its belonging obs. When aggregating packets into flows, the entry is an ``NFFlow`` object and the obs is an ``NFPacket`` object.

* ``on_expire(self, entry)`` [default=``pass``]

  - Method called at entry expiration. When aggregating packets into flows, the entry is an ``NFFlow``

* ``cleanup(self)`` [default=``pass``]

  - Method called for plugin cleanup.

In the following, we want to run an early classification of flows based on a trained machine learning model than takes
as features the 3 first packets size of a flow.

***************************
Computing required features
***************************

.. code-block:: python

    from nfstream import NFPlugin

    class feat_1(NFPlugin):
        def on_update(self, obs, entry):
            if entry.packets == 1:
                entry.feat_1 == obs.length

    class feat_2(NFPlugin):
        def on_update(self, obs, entry):
            if entry.packets == 1:
                entry.feat_2 == obs.length

    class feat_3(NFPlugin):
        def on_update(self, obs, entry):
            if entry.packets == 3:
                entry.feat_3 == obs.length

************************
Trained model prediction
************************

.. code-block:: python

    class model_prediction(NFPlugin):
        def on_update(self, obs, entry):
            if entry.packets ==3:
                entry.model_prediction = self.user_data.predict_proba([entry.feat_1 , entry.feat_2 , entry.feat_3])
                # optionally we can force NFStreamer to immediately expires the flow
                # entry.expiration_id = -1


***********************
Start your new streamer
***********************

.. code-block:: python

   my_model = function_to_load_your_model() # or whatever
   ml_streamer = NFStreamer(source='devil.pcap',
                            plugins=[feat_1(volatile=True),
                                     feat_2(volatile=True),
                                     feat_3(volatile=True),
                                     model_prediction(user_data=my_model)
                                     ])
   for flow in ml_streamer:
        print(flow.model_prediction) # now you will see your trained model prediction as part of the flow :)