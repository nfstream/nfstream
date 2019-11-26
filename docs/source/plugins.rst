##################
Extending nfstream
##################

nfstream is designed to be flexible and machine learning oriented. In the following section, we depict the use of NFPlugin
in both cases.

.. code-block:: python

    from nfstream import NFPlugin

    class my_awesome_plugin(NFPlugin):
        def process(self, pkt, flow):
            if pkt.length >= 666:
                flow.my_awesome_plugin += 1

   streamer_awesome = NFStreamer(source='devil.pcap', plugins=[my_awesome_plugin()])
   for flow in streamer_awesome:
      print(flow.my_awesome_plugin) # now you will see your dynamically created metric in generated flows

*******************
NFPlugin parameters
*******************
* ``name`` [default= ``class name`` ]

  - Plugin name. Must be unique as it's dynamically created as a flow attribute.

* ``volatile`` [default=False]

  - Volatile plugin is available only when flow is processed. At flow expiration level, plugin is automatically removed (will not appear as flow attribute).

* ``init_function`` [default=lambda packet:0]

  - Function called at flow creation (First NFPacket as argument).

****************
NFPlugin methods
****************
* ``process(NFPacket, NFFlow)``

  - Method called to update each NFFlow with its belonging NFPacket.

* ``giveup(NFFlow)`` [default=pass]

  - Method called at flow expiration.


###########
Get Started
###########

In the following, we want to run an early classification of flows based on a trained machine learning model than takes
as features the 3 first packets size of a flow.

**************************
Building required features
**************************

.. code-block:: python

    from nfstream import NFPlugin

    class feat_1(NFPlugin):
        def process(self, pkt, flow):
            if flow.packets == 1:
                flow.feat_1 == pkt.length

    class feat_2(NFPlugin):
        def process(self, pkt, flow):
            if flow.packets == 1:
                flow.feat_2 == pkt.length

    class feat_3(NFPlugin):
        def process(self, pkt, flow):
            if flow.packets == 3:
                flow.feat_3 == pkt.length

****************************
Add trained model prediction
****************************

.. code-block:: python

    trained_model = load_my_magic_model(path)
    class model_prediction(NFPlugin):
        def process(self, pkt, flow):
            if flow.packets ==3:
                flow.model_prediction = trained_model.predict_proba([flow.feat_1 , flow.feat_2 , flow.feat_3])
                # optionally we can force nfstream to immediately expires the flow
                flow.expiration_id = -1
